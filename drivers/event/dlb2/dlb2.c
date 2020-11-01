/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2020 Intel Corporation
 */

#include <assert.h>
#include <errno.h>
#include <nmmintrin.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/fcntl.h>

#include <rte_common.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_errno.h>
#include <rte_eventdev.h>
#include <rte_eventdev_pmd.h>
#include <rte_io.h>
#include <rte_kvargs.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>
#include <rte_ring.h>
#include <rte_string_fns.h>

#include "dlb2_priv.h"
#include "dlb2_iface.h"
#include "dlb2_inline_fns.h"

/*
 * Resources exposed to eventdev. Some values overridden at runtime using
 * values returned by the DLB kernel driver.
 */
#if (RTE_EVENT_MAX_QUEUES_PER_DEV > UINT8_MAX)
#error "RTE_EVENT_MAX_QUEUES_PER_DEV cannot fit in member max_event_queues"
#endif
static struct rte_event_dev_info evdev_dlb2_default_info = {
	.driver_name = "", /* probe will set */
	.min_dequeue_timeout_ns = DLB2_MIN_DEQUEUE_TIMEOUT_NS,
	.max_dequeue_timeout_ns = DLB2_MAX_DEQUEUE_TIMEOUT_NS,
#if (RTE_EVENT_MAX_QUEUES_PER_DEV < DLB2_MAX_NUM_LDB_QUEUES)
	.max_event_queues = RTE_EVENT_MAX_QUEUES_PER_DEV,
#else
	.max_event_queues = DLB2_MAX_NUM_LDB_QUEUES,
#endif
	.max_event_queue_flows = DLB2_MAX_NUM_FLOWS,
	.max_event_queue_priority_levels = DLB2_QID_PRIORITIES,
	.max_event_priority_levels = DLB2_QID_PRIORITIES,
	.max_event_ports = DLB2_MAX_NUM_LDB_PORTS,
	.max_event_port_dequeue_depth = DLB2_MAX_CQ_DEPTH,
	.max_event_port_enqueue_depth = DLB2_MAX_ENQUEUE_DEPTH,
	.max_event_port_links = DLB2_MAX_NUM_QIDS_PER_LDB_CQ,
	.max_num_events = DLB2_MAX_NUM_LDB_CREDITS,
	.max_single_link_event_port_queue_pairs = DLB2_MAX_NUM_DIR_PORTS,
	.event_dev_cap = (RTE_EVENT_DEV_CAP_QUEUE_QOS |
			  RTE_EVENT_DEV_CAP_EVENT_QOS |
			  RTE_EVENT_DEV_CAP_BURST_MODE |
			  RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED |
			  RTE_EVENT_DEV_CAP_IMPLICIT_RELEASE_DISABLE |
			  RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES),
};

struct process_local_port_data
dlb2_port[DLB2_MAX_NUM_PORTS][DLB2_NUM_PORT_TYPES];

/*
 * DUMMY - added so that xstats path will compile/link.
 * Will be replaced by real version in a subsequent
 * patch.
 */
uint32_t
dlb2_get_queue_depth(struct dlb2_eventdev *dlb2,
		     struct dlb2_eventdev_queue *queue)
{
	RTE_SET_USED(dlb2);
	RTE_SET_USED(queue);

	return 0;
}

static void
dlb2_free_qe_mem(struct dlb2_port *qm_port)
{
	if (qm_port == NULL)
		return;

	rte_free(qm_port->qe4);
	qm_port->qe4 = NULL;

	rte_free(qm_port->int_arm_qe);
	qm_port->int_arm_qe = NULL;

	rte_free(qm_port->consume_qe);
	qm_port->consume_qe = NULL;

	rte_memzone_free(dlb2_port[qm_port->id][PORT_TYPE(qm_port)].mz);
	dlb2_port[qm_port->id][PORT_TYPE(qm_port)].mz = NULL;
}

/* override defaults with value(s) provided on command line */
static void
dlb2_init_queue_depth_thresholds(struct dlb2_eventdev *dlb2,
				 int *qid_depth_thresholds)
{
	int q;

	for (q = 0; q < DLB2_MAX_NUM_QUEUES; q++) {
		if (qid_depth_thresholds[q] != 0)
			dlb2->ev_queues[q].depth_threshold =
				qid_depth_thresholds[q];
	}
}

static int
dlb2_hw_query_resources(struct dlb2_eventdev *dlb2)
{
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_hw_resource_info *dlb2_info = &handle->info;
	int ret;

	/* Query driver resources provisioned for this device */

	ret = dlb2_iface_get_num_resources(handle,
					   &dlb2->hw_rsrc_query_results);
	if (ret) {
		DLB2_LOG_ERR("ioctl get dlb2 num resources, err=%d\n", ret);
		return ret;
	}

	/* Complete filling in device resource info returned to evdev app,
	 * overriding any default values.
	 * The capabilities (CAPs) were set at compile time.
	 */

	evdev_dlb2_default_info.max_event_queues =
		dlb2->hw_rsrc_query_results.num_ldb_queues;

	evdev_dlb2_default_info.max_event_ports =
		dlb2->hw_rsrc_query_results.num_ldb_ports;

	evdev_dlb2_default_info.max_num_events =
		dlb2->hw_rsrc_query_results.num_ldb_credits;

	/* Save off values used when creating the scheduling domain. */

	handle->info.num_sched_domains =
		dlb2->hw_rsrc_query_results.num_sched_domains;

	handle->info.hw_rsrc_max.nb_events_limit =
		dlb2->hw_rsrc_query_results.num_ldb_credits;

	handle->info.hw_rsrc_max.num_queues =
		dlb2->hw_rsrc_query_results.num_ldb_queues +
		dlb2->hw_rsrc_query_results.num_dir_ports;

	handle->info.hw_rsrc_max.num_ldb_queues =
		dlb2->hw_rsrc_query_results.num_ldb_queues;

	handle->info.hw_rsrc_max.num_ldb_ports =
		dlb2->hw_rsrc_query_results.num_ldb_ports;

	handle->info.hw_rsrc_max.num_dir_ports =
		dlb2->hw_rsrc_query_results.num_dir_ports;

	handle->info.hw_rsrc_max.reorder_window_size =
		dlb2->hw_rsrc_query_results.num_hist_list_entries;

	rte_memcpy(dlb2_info, &handle->info.hw_rsrc_max, sizeof(*dlb2_info));

	return 0;
}

#define DLB2_BASE_10 10

static int
dlb2_string_to_int(int *result, const char *str)
{
	long ret;
	char *endptr;

	if (str == NULL || result == NULL)
		return -EINVAL;

	errno = 0;
	ret = strtol(str, &endptr, DLB2_BASE_10);
	if (errno)
		return -errno;

	/* long int and int may be different width for some architectures */
	if (ret < INT_MIN || ret > INT_MAX || endptr == str)
		return -EINVAL;

	*result = ret;
	return 0;
}

static int
set_numa_node(const char *key __rte_unused, const char *value, void *opaque)
{
	int *socket_id = opaque;
	int ret;

	ret = dlb2_string_to_int(socket_id, value);
	if (ret < 0)
		return ret;

	if (*socket_id > RTE_MAX_NUMA_NODES)
		return -EINVAL;
	return 0;
}

static int
set_max_num_events(const char *key __rte_unused,
		   const char *value,
		   void *opaque)
{
	int *max_num_events = opaque;
	int ret;

	if (value == NULL || opaque == NULL) {
		DLB2_LOG_ERR("NULL pointer\n");
		return -EINVAL;
	}

	ret = dlb2_string_to_int(max_num_events, value);
	if (ret < 0)
		return ret;

	if (*max_num_events < 0 || *max_num_events >
			DLB2_MAX_NUM_LDB_CREDITS) {
		DLB2_LOG_ERR("dlb2: max_num_events must be between 0 and %d\n",
			     DLB2_MAX_NUM_LDB_CREDITS);
		return -EINVAL;
	}

	return 0;
}

static int
set_num_dir_credits(const char *key __rte_unused,
		    const char *value,
		    void *opaque)
{
	int *num_dir_credits = opaque;
	int ret;

	if (value == NULL || opaque == NULL) {
		DLB2_LOG_ERR("NULL pointer\n");
		return -EINVAL;
	}

	ret = dlb2_string_to_int(num_dir_credits, value);
	if (ret < 0)
		return ret;

	if (*num_dir_credits < 0 ||
	    *num_dir_credits > DLB2_MAX_NUM_DIR_CREDITS) {
		DLB2_LOG_ERR("dlb2: num_dir_credits must be between 0 and %d\n",
			     DLB2_MAX_NUM_DIR_CREDITS);
		return -EINVAL;
	}

	return 0;
}

static int
set_dev_id(const char *key __rte_unused,
	   const char *value,
	   void *opaque)
{
	int *dev_id = opaque;
	int ret;

	if (value == NULL || opaque == NULL) {
		DLB2_LOG_ERR("NULL pointer\n");
		return -EINVAL;
	}

	ret = dlb2_string_to_int(dev_id, value);
	if (ret < 0)
		return ret;

	return 0;
}

static int
set_cos(const char *key __rte_unused,
	const char *value,
	void *opaque)
{
	enum dlb2_cos *cos_id = opaque;
	int x = 0;
	int ret;

	if (value == NULL || opaque == NULL) {
		DLB2_LOG_ERR("NULL pointer\n");
		return -EINVAL;
	}

	ret = dlb2_string_to_int(&x, value);
	if (ret < 0)
		return ret;

	if (x != DLB2_COS_DEFAULT && (x < DLB2_COS_0 || x > DLB2_COS_3)) {
		DLB2_LOG_ERR(
			"COS %d out of range, must be DLB2_COS_DEFAULT or 0-3\n",
			x);
		return -EINVAL;
	}

	*cos_id = x;

	return 0;
}


static int
set_qid_depth_thresh(const char *key __rte_unused,
		     const char *value,
		     void *opaque)
{
	struct dlb2_qid_depth_thresholds *qid_thresh = opaque;
	int first, last, thresh, i;

	if (value == NULL || opaque == NULL) {
		DLB2_LOG_ERR("NULL pointer\n");
		return -EINVAL;
	}

	/* command line override may take one of the following 3 forms:
	 * qid_depth_thresh=all:<threshold_value> ... all queues
	 * qid_depth_thresh=qidA-qidB:<threshold_value> ... a range of queues
	 * qid_depth_thresh=qid:<threshold_value> ... just one queue
	 */
	if (sscanf(value, "all:%d", &thresh) == 1) {
		first = 0;
		last = DLB2_MAX_NUM_QUEUES - 1;
	} else if (sscanf(value, "%d-%d:%d", &first, &last, &thresh) == 3) {
		/* we have everything we need */
	} else if (sscanf(value, "%d:%d", &first, &thresh) == 2) {
		last = first;
	} else {
		DLB2_LOG_ERR("Error parsing qid depth devarg. Should be all:val, qid-qid:val, or qid:val\n");
		return -EINVAL;
	}

	if (first > last || first < 0 || last >= DLB2_MAX_NUM_QUEUES) {
		DLB2_LOG_ERR("Error parsing qid depth devarg, invalid qid value\n");
		return -EINVAL;
	}

	if (thresh < 0 || thresh > DLB2_MAX_QUEUE_DEPTH_THRESHOLD) {
		DLB2_LOG_ERR("Error parsing qid depth devarg, threshold > %d\n",
			     DLB2_MAX_QUEUE_DEPTH_THRESHOLD);
		return -EINVAL;
	}

	for (i = first; i <= last; i++)
		qid_thresh->val[i] = thresh; /* indexed by qid */

	return 0;
}

static void
dlb2_eventdev_info_get(struct rte_eventdev *dev,
		       struct rte_event_dev_info *dev_info)
{
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);
	int ret;

	ret = dlb2_hw_query_resources(dlb2);
	if (ret) {
		const struct rte_eventdev_data *data = dev->data;

		DLB2_LOG_ERR("get resources err=%d, devid=%d\n",
			     ret, data->dev_id);
		/* fn is void, so fall through and return values set up in
		 * probe
		 */
	}

	/* Add num resources currently owned by this domain.
	 * These would become available if the scheduling domain were reset due
	 * to the application recalling eventdev_configure to *reconfigure* the
	 * domain.
	 */
	evdev_dlb2_default_info.max_event_ports += dlb2->num_ldb_ports;
	evdev_dlb2_default_info.max_event_queues += dlb2->num_ldb_queues;
	evdev_dlb2_default_info.max_num_events += dlb2->max_ldb_credits;

	evdev_dlb2_default_info.max_event_queues =
		RTE_MIN(evdev_dlb2_default_info.max_event_queues,
			RTE_EVENT_MAX_QUEUES_PER_DEV);

	evdev_dlb2_default_info.max_num_events =
		RTE_MIN(evdev_dlb2_default_info.max_num_events,
			dlb2->max_num_events_override);

	*dev_info = evdev_dlb2_default_info;
}

static int
dlb2_hw_create_sched_domain(struct dlb2_hw_dev *handle,
			    const struct dlb2_hw_rsrcs *resources_asked)
{
	int ret = 0;
	struct dlb2_create_sched_domain_args *cfg;

	if (resources_asked == NULL) {
		DLB2_LOG_ERR("dlb2: dlb2_create NULL parameter\n");
		ret = EINVAL;
		goto error_exit;
	}

	/* Map generic qm resources to dlb2 resources */
	cfg = &handle->cfg.resources;

	/* DIR ports and queues */

	cfg->num_dir_ports = resources_asked->num_dir_ports;

	cfg->num_dir_credits = resources_asked->num_dir_credits;

	/* LDB queues */

	cfg->num_ldb_queues = resources_asked->num_ldb_queues;

	/* LDB ports */

	cfg->cos_strict = 0; /* Best effort */
	cfg->num_cos_ldb_ports[0] = 0;
	cfg->num_cos_ldb_ports[1] = 0;
	cfg->num_cos_ldb_ports[2] = 0;
	cfg->num_cos_ldb_ports[3] = 0;

	switch (handle->cos_id) {
	case DLB2_COS_0:
		cfg->num_ldb_ports = 0; /* no don't care ports */
		cfg->num_cos_ldb_ports[0] =
			resources_asked->num_ldb_ports;
		break;
	case DLB2_COS_1:
		cfg->num_ldb_ports = 0; /* no don't care ports */
		cfg->num_cos_ldb_ports[1] = resources_asked->num_ldb_ports;
		break;
	case DLB2_COS_2:
		cfg->num_ldb_ports = 0; /* no don't care ports */
		cfg->num_cos_ldb_ports[2] = resources_asked->num_ldb_ports;
		break;
	case DLB2_COS_3:
		cfg->num_ldb_ports = 0; /* no don't care ports */
		cfg->num_cos_ldb_ports[3] =
			resources_asked->num_ldb_ports;
		break;
	case DLB2_COS_DEFAULT:
		/* all ldb ports are don't care ports from a cos perspective */
		cfg->num_ldb_ports =
			resources_asked->num_ldb_ports;
		break;
	}

	cfg->num_ldb_credits =
		resources_asked->num_ldb_credits;

	cfg->num_atomic_inflights =
		DLB2_NUM_ATOMIC_INFLIGHTS_PER_QUEUE *
		cfg->num_ldb_queues;

	cfg->num_hist_list_entries = resources_asked->num_ldb_ports *
		DLB2_NUM_HIST_LIST_ENTRIES_PER_LDB_PORT;

	DLB2_LOG_DBG("sched domain create - ldb_qs=%d, ldb_ports=%d, dir_ports=%d, atomic_inflights=%d, hist_list_entries=%d, ldb_credits=%d, dir_credits=%d\n",
		     cfg->num_ldb_queues,
		     resources_asked->num_ldb_ports,
		     cfg->num_dir_ports,
		     cfg->num_atomic_inflights,
		     cfg->num_hist_list_entries,
		     cfg->num_ldb_credits,
		     cfg->num_dir_credits);

	/* Configure the QM */

	ret = dlb2_iface_sched_domain_create(handle, cfg);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: domain create failed, ret = %d, extra status: %s\n",
			     ret,
			     dlb2_error_strings[cfg->response.status]);

		goto error_exit;
	}

	handle->domain_id = cfg->response.id;
	handle->cfg.configured = true;

error_exit:

	return ret;
}

static void
dlb2_hw_reset_sched_domain(const struct rte_eventdev *dev, bool reconfig)
{
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);
	enum dlb2_configuration_state config_state;
	int i, j;

	dlb2_iface_domain_reset(dlb2);

	/* Free all dynamically allocated port memory */
	for (i = 0; i < dlb2->num_ports; i++)
		dlb2_free_qe_mem(&dlb2->ev_ports[i].qm_port);

	/* If reconfiguring, mark the device's queues and ports as "previously
	 * configured." If the user doesn't reconfigure them, the PMD will
	 * reapply their previous configuration when the device is started.
	 */
	config_state = (reconfig) ? DLB2_PREV_CONFIGURED :
		DLB2_NOT_CONFIGURED;

	for (i = 0; i < dlb2->num_ports; i++) {
		dlb2->ev_ports[i].qm_port.config_state = config_state;
		/* Reset setup_done so ports can be reconfigured */
		dlb2->ev_ports[i].setup_done = false;
		for (j = 0; j < DLB2_MAX_NUM_QIDS_PER_LDB_CQ; j++)
			dlb2->ev_ports[i].link[j].mapped = false;
	}

	for (i = 0; i < dlb2->num_queues; i++)
		dlb2->ev_queues[i].qm_queue.config_state = config_state;

	for (i = 0; i < DLB2_MAX_NUM_QUEUES; i++)
		dlb2->ev_queues[i].setup_done = false;

	dlb2->num_ports = 0;
	dlb2->num_ldb_ports = 0;
	dlb2->num_dir_ports = 0;
	dlb2->num_queues = 0;
	dlb2->num_ldb_queues = 0;
	dlb2->num_dir_queues = 0;
	dlb2->configured = false;
}

/* Note: 1 QM instance per QM device, QM instance/device == event device */
static int
dlb2_eventdev_configure(const struct rte_eventdev *dev)
{
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_hw_rsrcs *rsrcs = &handle->info.hw_rsrc_max;
	const struct rte_eventdev_data *data = dev->data;
	const struct rte_event_dev_config *config = &data->dev_conf;
	int ret;

	/* If this eventdev is already configured, we must release the current
	 * scheduling domain before attempting to configure a new one.
	 */
	if (dlb2->configured) {
		dlb2_hw_reset_sched_domain(dev, true);

		ret = dlb2_hw_query_resources(dlb2);
		if (ret) {
			DLB2_LOG_ERR("get resources err=%d, devid=%d\n",
				     ret, data->dev_id);
			return ret;
		}
	}

	if (config->nb_event_queues > rsrcs->num_queues) {
		DLB2_LOG_ERR("nb_event_queues parameter (%d) exceeds the QM device's capabilities (%d).\n",
			     config->nb_event_queues,
			     rsrcs->num_queues);
		return -EINVAL;
	}
	if (config->nb_event_ports > (rsrcs->num_ldb_ports
			+ rsrcs->num_dir_ports)) {
		DLB2_LOG_ERR("nb_event_ports parameter (%d) exceeds the QM device's capabilities (%d).\n",
			     config->nb_event_ports,
			     (rsrcs->num_ldb_ports + rsrcs->num_dir_ports));
		return -EINVAL;
	}
	if (config->nb_events_limit > rsrcs->nb_events_limit) {
		DLB2_LOG_ERR("nb_events_limit parameter (%d) exceeds the QM device's capabilities (%d).\n",
			     config->nb_events_limit,
			     rsrcs->nb_events_limit);
		return -EINVAL;
	}

	if (config->event_dev_cfg & RTE_EVENT_DEV_CFG_PER_DEQUEUE_TIMEOUT)
		dlb2->global_dequeue_wait = false;
	else {
		uint32_t timeout32;

		dlb2->global_dequeue_wait = true;

		/* note size mismatch of timeout vals in eventdev lib. */
		timeout32 = config->dequeue_timeout_ns;

		dlb2->global_dequeue_wait_ticks =
			timeout32 * (rte_get_timer_hz() / 1E9);
	}

	/* Does this platform support umonitor/umwait? */
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_WAITPKG)) {
		if (RTE_LIBRTE_PMD_DLB2_UMWAIT_CTL_STATE != 0 &&
		    RTE_LIBRTE_PMD_DLB2_UMWAIT_CTL_STATE != 1) {
			DLB2_LOG_ERR("invalid value (%d) for RTE_LIBRTE_PMD_DLB2_UMWAIT_CTL_STATE, must be 0 or 1.\n",
				     RTE_LIBRTE_PMD_DLB2_UMWAIT_CTL_STATE);
			return -EINVAL;
		}
		dlb2->umwait_allowed = true;
	}

	rsrcs->num_dir_ports = config->nb_single_link_event_port_queues;
	rsrcs->num_ldb_ports  = config->nb_event_ports - rsrcs->num_dir_ports;
	/* 1 dir queue per dir port */
	rsrcs->num_ldb_queues = config->nb_event_queues - rsrcs->num_dir_ports;

	/* Scale down nb_events_limit by 4 for directed credits, since there
	 * are 4x as many load-balanced credits.
	 */
	rsrcs->num_ldb_credits = 0;
	rsrcs->num_dir_credits = 0;

	if (rsrcs->num_ldb_queues)
		rsrcs->num_ldb_credits = config->nb_events_limit;
	if (rsrcs->num_dir_ports)
		rsrcs->num_dir_credits = config->nb_events_limit / 4;
	if (dlb2->num_dir_credits_override != -1)
		rsrcs->num_dir_credits = dlb2->num_dir_credits_override;

	if (dlb2_hw_create_sched_domain(handle, rsrcs) < 0) {
		DLB2_LOG_ERR("dlb2_hw_create_sched_domain failed\n");
		return -ENODEV;
	}

	dlb2->new_event_limit = config->nb_events_limit;
	__atomic_store_n(&dlb2->inflights, 0, __ATOMIC_SEQ_CST);

	/* Save number of ports/queues for this event dev */
	dlb2->num_ports = config->nb_event_ports;
	dlb2->num_queues = config->nb_event_queues;
	dlb2->num_dir_ports = rsrcs->num_dir_ports;
	dlb2->num_ldb_ports = dlb2->num_ports - dlb2->num_dir_ports;
	dlb2->num_ldb_queues = dlb2->num_queues - dlb2->num_dir_ports;
	dlb2->num_dir_queues = dlb2->num_dir_ports;
	dlb2->ldb_credit_pool = rsrcs->num_ldb_credits;
	dlb2->max_ldb_credits = rsrcs->num_ldb_credits;
	dlb2->dir_credit_pool = rsrcs->num_dir_credits;
	dlb2->max_dir_credits = rsrcs->num_dir_credits;

	dlb2->configured = true;

	return 0;
}

static void
dlb2_eventdev_port_default_conf_get(struct rte_eventdev *dev,
				    uint8_t port_id,
				    struct rte_event_port_conf *port_conf)
{
	RTE_SET_USED(port_id);
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);

	port_conf->new_event_threshold = dlb2->new_event_limit;
	port_conf->dequeue_depth = 32;
	port_conf->enqueue_depth = DLB2_MAX_ENQUEUE_DEPTH;
	port_conf->event_port_cfg = 0;
}

static void
dlb2_eventdev_queue_default_conf_get(struct rte_eventdev *dev,
				     uint8_t queue_id,
				     struct rte_event_queue_conf *queue_conf)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(queue_id);

	queue_conf->nb_atomic_flows = 1024;
	queue_conf->nb_atomic_order_sequences = 64;
	queue_conf->event_queue_cfg = 0;
	queue_conf->priority = 0;
}

static int32_t
dlb2_get_sn_allocation(struct dlb2_eventdev *dlb2, int group)
{
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_get_sn_allocation_args cfg;
	int ret;

	cfg.group = group;

	ret = dlb2_iface_get_sn_allocation(handle, &cfg);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: get_sn_allocation ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		return ret;
	}

	return cfg.response.id;
}

static int
dlb2_set_sn_allocation(struct dlb2_eventdev *dlb2, int group, int num)
{
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_set_sn_allocation_args cfg;
	int ret;

	cfg.num = num;
	cfg.group = group;

	ret = dlb2_iface_set_sn_allocation(handle, &cfg);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: set_sn_allocation ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		return ret;
	}

	return ret;
}

static int32_t
dlb2_get_sn_occupancy(struct dlb2_eventdev *dlb2, int group)
{
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_get_sn_occupancy_args cfg;
	int ret;

	cfg.group = group;

	ret = dlb2_iface_get_sn_occupancy(handle, &cfg);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: get_sn_occupancy ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		return ret;
	}

	return cfg.response.id;
}

/* Query the current sequence number allocations and, if they conflict with the
 * requested LDB queue configuration, attempt to re-allocate sequence numbers.
 * This is best-effort; if it fails, the PMD will attempt to configure the
 * load-balanced queue and return an error.
 */
static void
dlb2_program_sn_allocation(struct dlb2_eventdev *dlb2,
			   const struct rte_event_queue_conf *queue_conf)
{
	int grp_occupancy[DLB2_NUM_SN_GROUPS];
	int grp_alloc[DLB2_NUM_SN_GROUPS];
	int i, sequence_numbers;

	sequence_numbers = (int)queue_conf->nb_atomic_order_sequences;

	for (i = 0; i < DLB2_NUM_SN_GROUPS; i++) {
		int total_slots;

		grp_alloc[i] = dlb2_get_sn_allocation(dlb2, i);
		if (grp_alloc[i] < 0)
			return;

		total_slots = DLB2_MAX_LDB_SN_ALLOC / grp_alloc[i];

		grp_occupancy[i] = dlb2_get_sn_occupancy(dlb2, i);
		if (grp_occupancy[i] < 0)
			return;

		/* DLB has at least one available slot for the requested
		 * sequence numbers, so no further configuration required.
		 */
		if (grp_alloc[i] == sequence_numbers &&
		    grp_occupancy[i] < total_slots)
			return;
	}

	/* None of the sequence number groups are configured for the requested
	 * sequence numbers, so we have to reconfigure one of them. This is
	 * only possible if a group is not in use.
	 */
	for (i = 0; i < DLB2_NUM_SN_GROUPS; i++) {
		if (grp_occupancy[i] == 0)
			break;
	}

	if (i == DLB2_NUM_SN_GROUPS) {
		DLB2_LOG_ERR("[%s()] No groups with %d sequence_numbers are available or have free slots\n",
		       __func__, sequence_numbers);
		return;
	}

	/* Attempt to configure slot i with the requested number of sequence
	 * numbers. Ignore the return value -- if this fails, the error will be
	 * caught during subsequent queue configuration.
	 */
	dlb2_set_sn_allocation(dlb2, i, sequence_numbers);
}

static int32_t
dlb2_hw_create_ldb_queue(struct dlb2_eventdev *dlb2,
			 struct dlb2_eventdev_queue *ev_queue,
			 const struct rte_event_queue_conf *evq_conf)
{
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_queue *queue = &ev_queue->qm_queue;
	struct dlb2_create_ldb_queue_args cfg;
	int32_t ret;
	uint32_t qm_qid;
	int sched_type = -1;

	if (evq_conf == NULL)
		return -EINVAL;

	if (evq_conf->event_queue_cfg & RTE_EVENT_QUEUE_CFG_ALL_TYPES) {
		if (evq_conf->nb_atomic_order_sequences != 0)
			sched_type = RTE_SCHED_TYPE_ORDERED;
		else
			sched_type = RTE_SCHED_TYPE_PARALLEL;
	} else
		sched_type = evq_conf->schedule_type;

	cfg.num_atomic_inflights = DLB2_NUM_ATOMIC_INFLIGHTS_PER_QUEUE;
	cfg.num_sequence_numbers = evq_conf->nb_atomic_order_sequences;
	cfg.num_qid_inflights = evq_conf->nb_atomic_order_sequences;

	if (sched_type != RTE_SCHED_TYPE_ORDERED) {
		cfg.num_sequence_numbers = 0;
		cfg.num_qid_inflights = 2048;
	}

	/* App should set this to the number of hardware flows they want, not
	 * the overall number of flows they're going to use. E.g. if app is
	 * using 64 flows and sets compression to 64, best-case they'll get
	 * 64 unique hashed flows in hardware.
	 */
	switch (evq_conf->nb_atomic_flows) {
	/* Valid DLB2 compression levels */
	case 64:
	case 128:
	case 256:
	case 512:
	case (1 * 1024): /* 1K */
	case (2 * 1024): /* 2K */
	case (4 * 1024): /* 4K */
	case (64 * 1024): /* 64K */
		cfg.lock_id_comp_level = evq_conf->nb_atomic_flows;
		break;
	default:
		/* Invalid compression level */
		cfg.lock_id_comp_level = 0; /* no compression */
	}

	if (ev_queue->depth_threshold == 0) {
		cfg.depth_threshold = RTE_PMD_DLB2_DEFAULT_DEPTH_THRESH;
		ev_queue->depth_threshold = RTE_PMD_DLB2_DEFAULT_DEPTH_THRESH;
	} else
		cfg.depth_threshold = ev_queue->depth_threshold;

	ret = dlb2_iface_ldb_queue_create(handle, &cfg);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: create LB event queue error, ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		return -EINVAL;
	}

	qm_qid = cfg.response.id;

	/* Save off queue config for debug, resource lookups, and reconfig */
	queue->num_qid_inflights = cfg.num_qid_inflights;
	queue->num_atm_inflights = cfg.num_atomic_inflights;

	queue->sched_type = sched_type;
	queue->config_state = DLB2_CONFIGURED;

	DLB2_LOG_DBG("Created LB event queue %d, nb_inflights=%d, nb_seq=%d, qid inflights=%d\n",
		     qm_qid,
		     cfg.num_atomic_inflights,
		     cfg.num_sequence_numbers,
		     cfg.num_qid_inflights);

	return qm_qid;
}

static int
dlb2_eventdev_ldb_queue_setup(struct rte_eventdev *dev,
			      struct dlb2_eventdev_queue *ev_queue,
			      const struct rte_event_queue_conf *queue_conf)
{
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);
	int32_t qm_qid;

	if (queue_conf->nb_atomic_order_sequences)
		dlb2_program_sn_allocation(dlb2, queue_conf);

	qm_qid = dlb2_hw_create_ldb_queue(dlb2, ev_queue, queue_conf);
	if (qm_qid < 0) {
		DLB2_LOG_ERR("Failed to create the load-balanced queue\n");

		return qm_qid;
	}

	dlb2->qm_ldb_to_ev_queue_id[qm_qid] = ev_queue->id;

	ev_queue->qm_queue.id = qm_qid;

	return 0;
}

static int dlb2_num_dir_queues_setup(struct dlb2_eventdev *dlb2)
{
	int i, num = 0;

	for (i = 0; i < dlb2->num_queues; i++) {
		if (dlb2->ev_queues[i].setup_done &&
		    dlb2->ev_queues[i].qm_queue.is_directed)
			num++;
	}

	return num;
}

static void
dlb2_queue_link_teardown(struct dlb2_eventdev *dlb2,
			 struct dlb2_eventdev_queue *ev_queue)
{
	struct dlb2_eventdev_port *ev_port;
	int i, j;

	for (i = 0; i < dlb2->num_ports; i++) {
		ev_port = &dlb2->ev_ports[i];

		for (j = 0; j < DLB2_MAX_NUM_QIDS_PER_LDB_CQ; j++) {
			if (!ev_port->link[j].valid ||
			    ev_port->link[j].queue_id != ev_queue->id)
				continue;

			ev_port->link[j].valid = false;
			ev_port->num_links--;
		}
	}

	ev_queue->num_links = 0;
}

static int
dlb2_eventdev_queue_setup(struct rte_eventdev *dev,
			  uint8_t ev_qid,
			  const struct rte_event_queue_conf *queue_conf)
{
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);
	struct dlb2_eventdev_queue *ev_queue;
	int ret;

	if (queue_conf == NULL)
		return -EINVAL;

	if (ev_qid >= dlb2->num_queues)
		return -EINVAL;

	ev_queue = &dlb2->ev_queues[ev_qid];

	ev_queue->qm_queue.is_directed = queue_conf->event_queue_cfg &
		RTE_EVENT_QUEUE_CFG_SINGLE_LINK;
	ev_queue->id = ev_qid;
	ev_queue->conf = *queue_conf;

	if (!ev_queue->qm_queue.is_directed) {
		ret = dlb2_eventdev_ldb_queue_setup(dev, ev_queue, queue_conf);
	} else {
		/* The directed queue isn't setup until link time, at which
		 * point we know its directed port ID. Directed queue setup
		 * will only fail if this queue is already setup or there are
		 * no directed queues left to configure.
		 */
		ret = 0;

		ev_queue->qm_queue.config_state = DLB2_NOT_CONFIGURED;

		if (ev_queue->setup_done ||
		    dlb2_num_dir_queues_setup(dlb2) == dlb2->num_dir_queues)
			ret = -EINVAL;
	}

	/* Tear down pre-existing port->queue links */
	if (!ret && dlb2->run_state == DLB2_RUN_STATE_STOPPED)
		dlb2_queue_link_teardown(dlb2, ev_queue);

	if (!ret)
		ev_queue->setup_done = true;

	return ret;
}

static int
dlb2_init_consume_qe(struct dlb2_port *qm_port, char *mz_name)
{
	struct dlb2_cq_pop_qe *qe;

	qe = rte_zmalloc(mz_name,
			DLB2_NUM_QES_PER_CACHE_LINE *
				sizeof(struct dlb2_cq_pop_qe),
			RTE_CACHE_LINE_SIZE);

	if (qe == NULL)	{
		DLB2_LOG_ERR("dlb2: no memory for consume_qe\n");
		return -ENOMEM;
	}
	qm_port->consume_qe = qe;

	qe->qe_valid = 0;
	qe->qe_frag = 0;
	qe->qe_comp = 0;
	qe->cq_token = 1;
	/* Tokens value is 0-based; i.e. '0' returns 1 token, '1' returns 2,
	 * and so on.
	 */
	qe->tokens = 0;	/* set at run time */
	qe->meas_lat = 0;
	qe->no_dec = 0;
	/* Completion IDs are disabled */
	qe->cmp_id = 0;

	return 0;
}

static int
dlb2_init_int_arm_qe(struct dlb2_port *qm_port, char *mz_name)
{
	struct dlb2_enqueue_qe *qe;

	qe = rte_zmalloc(mz_name,
			DLB2_NUM_QES_PER_CACHE_LINE *
				sizeof(struct dlb2_enqueue_qe),
			RTE_CACHE_LINE_SIZE);

	if (qe == NULL) {
		DLB2_LOG_ERR("dlb2: no memory for complete_qe\n");
		return -ENOMEM;
	}
	qm_port->int_arm_qe = qe;

	/* V2 - INT ARM is CQ_TOKEN + FRAG */
	qe->qe_valid = 0;
	qe->qe_frag = 1;
	qe->qe_comp = 0;
	qe->cq_token = 1;
	qe->meas_lat = 0;
	qe->no_dec = 0;
	/* Completion IDs are disabled */
	qe->cmp_id = 0;

	return 0;
}

static int
dlb2_init_qe_mem(struct dlb2_port *qm_port, char *mz_name)
{
	int ret, sz;

	sz = DLB2_NUM_QES_PER_CACHE_LINE * sizeof(struct dlb2_enqueue_qe);

	qm_port->qe4 = rte_zmalloc(mz_name, sz, RTE_CACHE_LINE_SIZE);

	if (qm_port->qe4 == NULL) {
		DLB2_LOG_ERR("dlb2: no qe4 memory\n");
		ret = -ENOMEM;
		goto error_exit;
	}

	ret = dlb2_init_int_arm_qe(qm_port, mz_name);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: dlb2_init_int_arm_qe ret=%d\n", ret);
		goto error_exit;
	}

	ret = dlb2_init_consume_qe(qm_port, mz_name);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: dlb2_init_consume_qe ret=%d\n", ret);
		goto error_exit;
	}

	return 0;

error_exit:

	dlb2_free_qe_mem(qm_port);

	return ret;
}

static int
dlb2_hw_create_ldb_port(struct dlb2_eventdev *dlb2,
			struct dlb2_eventdev_port *ev_port,
			uint32_t dequeue_depth,
			uint32_t enqueue_depth)
{
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_create_ldb_port_args cfg = { {0} };
	int ret;
	struct dlb2_port *qm_port = NULL;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	uint32_t qm_port_id;
	uint16_t ldb_credit_high_watermark;
	uint16_t dir_credit_high_watermark;

	if (handle == NULL)
		return -EINVAL;

	if (dequeue_depth < DLB2_MIN_CQ_DEPTH) {
		DLB2_LOG_ERR("dlb2: invalid enqueue_depth, must be at least %d\n",
			     DLB2_MIN_CQ_DEPTH);
		return -EINVAL;
	}

	if (enqueue_depth < DLB2_MIN_ENQUEUE_DEPTH) {
		DLB2_LOG_ERR("dlb2: invalid enqueue_depth, must be at least %d\n",
			     DLB2_MIN_ENQUEUE_DEPTH);
		return -EINVAL;
	}

	rte_spinlock_lock(&handle->resource_lock);

	/* We round up to the next power of 2 if necessary */
	cfg.cq_depth = rte_align32pow2(dequeue_depth);
	cfg.cq_depth_threshold = 1;

	cfg.cq_history_list_size = DLB2_NUM_HIST_LIST_ENTRIES_PER_LDB_PORT;

	if (handle->cos_id == DLB2_COS_DEFAULT)
		cfg.cos_id = 0;
	else
		cfg.cos_id = handle->cos_id;

	cfg.cos_strict = 0;

	/* User controls the LDB high watermark via enqueue depth. The DIR high
	 * watermark is equal, unless the directed credit pool is too small.
	 */
	ldb_credit_high_watermark = enqueue_depth;

	/* If there are no directed ports, the kernel driver will ignore this
	 * port's directed credit settings. Don't use enqueue_depth if it would
	 * require more directed credits than are available.
	 */
	dir_credit_high_watermark =
		RTE_MIN(enqueue_depth,
			handle->cfg.num_dir_credits / dlb2->num_ports);

	/* Per QM values */

	ret = dlb2_iface_ldb_port_create(handle, &cfg,  dlb2->poll_mode);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: dlb2_ldb_port_create error, ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		goto error_exit;
	}

	qm_port_id = cfg.response.id;

	DLB2_LOG_DBG("dlb2: ev_port %d uses qm LB port %d <<<<<\n",
		     ev_port->id, qm_port_id);

	qm_port = &ev_port->qm_port;
	qm_port->ev_port = ev_port; /* back ptr */
	qm_port->dlb2 = dlb2; /* back ptr */
	/*
	 * Allocate and init local qe struct(s).
	 * Note: MOVDIR64 requires the enqueue QE (qe4) to be aligned.
	 */

	snprintf(mz_name, sizeof(mz_name), "dlb2_ldb_port%d",
		 ev_port->id);

	ret = dlb2_init_qe_mem(qm_port, mz_name);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: init_qe_mem failed, ret=%d\n", ret);
		goto error_exit;
	}

	qm_port->id = qm_port_id;

	qm_port->cached_ldb_credits = 0;
	qm_port->cached_dir_credits = 0;
	/* CQs with depth < 8 use an 8-entry queue, but withhold credits so
	 * the effective depth is smaller.
	 */
	qm_port->cq_depth = cfg.cq_depth <= 8 ? 8 : cfg.cq_depth;
	qm_port->cq_idx = 0;
	qm_port->cq_idx_unmasked = 0;

	if (dlb2->poll_mode == DLB2_CQ_POLL_MODE_SPARSE)
		qm_port->cq_depth_mask = (qm_port->cq_depth * 4) - 1;
	else
		qm_port->cq_depth_mask = qm_port->cq_depth - 1;

	qm_port->gen_bit_shift = __builtin_popcount(qm_port->cq_depth_mask);
	/* starting value of gen bit - it toggles at wrap time */
	qm_port->gen_bit = 1;

	qm_port->int_armed = false;

	/* Save off for later use in info and lookup APIs. */
	qm_port->qid_mappings = &dlb2->qm_ldb_to_ev_queue_id[0];

	qm_port->dequeue_depth = dequeue_depth;

	qm_port->owed_tokens = 0;
	qm_port->issued_releases = 0;

	/* Save config message too. */
	rte_memcpy(&qm_port->cfg.ldb, &cfg, sizeof(qm_port->cfg.ldb));

	/* update state */
	qm_port->state = PORT_STARTED; /* enabled at create time */
	qm_port->config_state = DLB2_CONFIGURED;

	qm_port->dir_credits = dir_credit_high_watermark;
	qm_port->ldb_credits = ldb_credit_high_watermark;
	qm_port->credit_pool[DLB2_DIR_QUEUE] = &dlb2->dir_credit_pool;
	qm_port->credit_pool[DLB2_LDB_QUEUE] = &dlb2->ldb_credit_pool;

	DLB2_LOG_DBG("dlb2: created ldb port %d, depth = %d, ldb credits=%d, dir credits=%d\n",
		     qm_port_id,
		     dequeue_depth,
		     qm_port->ldb_credits,
		     qm_port->dir_credits);

	rte_spinlock_unlock(&handle->resource_lock);

	return 0;

error_exit:

	if (qm_port)
		dlb2_free_qe_mem(qm_port);

	rte_spinlock_unlock(&handle->resource_lock);

	DLB2_LOG_ERR("dlb2: create ldb port failed!\n");

	return ret;
}

static void
dlb2_port_link_teardown(struct dlb2_eventdev *dlb2,
			struct dlb2_eventdev_port *ev_port)
{
	struct dlb2_eventdev_queue *ev_queue;
	int i;

	for (i = 0; i < DLB2_MAX_NUM_QIDS_PER_LDB_CQ; i++) {
		if (!ev_port->link[i].valid)
			continue;

		ev_queue = &dlb2->ev_queues[ev_port->link[i].queue_id];

		ev_port->link[i].valid = false;
		ev_port->num_links--;
		ev_queue->num_links--;
	}
}

static int
dlb2_hw_create_dir_port(struct dlb2_eventdev *dlb2,
			struct dlb2_eventdev_port *ev_port,
			uint32_t dequeue_depth,
			uint32_t enqueue_depth)
{
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_create_dir_port_args cfg = { {0} };
	int ret;
	struct dlb2_port *qm_port = NULL;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	uint32_t qm_port_id;
	uint16_t ldb_credit_high_watermark;
	uint16_t dir_credit_high_watermark;

	if (dlb2 == NULL || handle == NULL)
		return -EINVAL;

	if (dequeue_depth < DLB2_MIN_CQ_DEPTH) {
		DLB2_LOG_ERR("dlb2: invalid dequeue_depth, must be %d-%d\n",
			     DLB2_MIN_CQ_DEPTH, DLB2_MAX_INPUT_QUEUE_DEPTH);
		return -EINVAL;
	}

	if (enqueue_depth < DLB2_MIN_ENQUEUE_DEPTH) {
		DLB2_LOG_ERR("dlb2: invalid enqueue_depth, must be at least %d\n",
			     DLB2_MIN_ENQUEUE_DEPTH);
		return -EINVAL;
	}

	rte_spinlock_lock(&handle->resource_lock);

	/* Directed queues are configured at link time. */
	cfg.queue_id = -1;

	/* We round up to the next power of 2 if necessary */
	cfg.cq_depth = rte_align32pow2(dequeue_depth);
	cfg.cq_depth_threshold = 1;

	/* User controls the LDB high watermark via enqueue depth. The DIR high
	 * watermark is equal, unless the directed credit pool is too small.
	 */
	ldb_credit_high_watermark = enqueue_depth;

	/* Don't use enqueue_depth if it would require more directed credits
	 * than are available.
	 */
	dir_credit_high_watermark =
		RTE_MIN(enqueue_depth,
			handle->cfg.num_dir_credits / dlb2->num_ports);

	/* Per QM values */

	ret = dlb2_iface_dir_port_create(handle, &cfg,  dlb2->poll_mode);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: dlb2_dir_port_create error, ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		goto error_exit;
	}

	qm_port_id = cfg.response.id;

	DLB2_LOG_DBG("dlb2: ev_port %d uses qm DIR port %d <<<<<\n",
		     ev_port->id, qm_port_id);

	qm_port = &ev_port->qm_port;
	qm_port->ev_port = ev_port; /* back ptr */
	qm_port->dlb2 = dlb2;  /* back ptr */

	/*
	 * Init local qe struct(s).
	 * Note: MOVDIR64 requires the enqueue QE to be aligned
	 */

	snprintf(mz_name, sizeof(mz_name), "dlb2_dir_port%d",
		 ev_port->id);

	ret = dlb2_init_qe_mem(qm_port, mz_name);

	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: init_qe_mem failed, ret=%d\n", ret);
		goto error_exit;
	}

	qm_port->id = qm_port_id;

	qm_port->cached_ldb_credits = 0;
	qm_port->cached_dir_credits = 0;
	/* CQs with depth < 8 use an 8-entry queue, but withhold credits so
	 * the effective depth is smaller.
	 */
	qm_port->cq_depth = cfg.cq_depth <= 8 ? 8 : cfg.cq_depth;
	qm_port->cq_idx = 0;
	qm_port->cq_idx_unmasked = 0;

	if (dlb2->poll_mode == DLB2_CQ_POLL_MODE_SPARSE)
		qm_port->cq_depth_mask = (cfg.cq_depth * 4) - 1;
	else
		qm_port->cq_depth_mask = cfg.cq_depth - 1;

	qm_port->gen_bit_shift = __builtin_popcount(qm_port->cq_depth_mask);
	/* starting value of gen bit - it toggles at wrap time */
	qm_port->gen_bit = 1;

	qm_port->int_armed = false;

	/* Save off for later use in info and lookup APIs. */
	qm_port->qid_mappings = &dlb2->qm_dir_to_ev_queue_id[0];

	qm_port->dequeue_depth = dequeue_depth;

	qm_port->owed_tokens = 0;
	qm_port->issued_releases = 0;

	/* Save config message too. */
	rte_memcpy(&qm_port->cfg.dir, &cfg, sizeof(qm_port->cfg.dir));

	/* update state */
	qm_port->state = PORT_STARTED; /* enabled at create time */
	qm_port->config_state = DLB2_CONFIGURED;

	qm_port->dir_credits = dir_credit_high_watermark;
	qm_port->ldb_credits = ldb_credit_high_watermark;
	qm_port->credit_pool[DLB2_DIR_QUEUE] = &dlb2->dir_credit_pool;
	qm_port->credit_pool[DLB2_LDB_QUEUE] = &dlb2->ldb_credit_pool;

	DLB2_LOG_DBG("dlb2: created dir port %d, depth = %d cr=%d,%d\n",
		     qm_port_id,
		     dequeue_depth,
		     dir_credit_high_watermark,
		     ldb_credit_high_watermark);

	rte_spinlock_unlock(&handle->resource_lock);

	return 0;

error_exit:

	if (qm_port)
		dlb2_free_qe_mem(qm_port);

	rte_spinlock_unlock(&handle->resource_lock);

	DLB2_LOG_ERR("dlb2: create dir port failed!\n");

	return ret;
}

static int
dlb2_eventdev_port_setup(struct rte_eventdev *dev,
			 uint8_t ev_port_id,
			 const struct rte_event_port_conf *port_conf)
{
	struct dlb2_eventdev *dlb2;
	struct dlb2_eventdev_port *ev_port;
	int ret;

	if (dev == NULL || port_conf == NULL) {
		DLB2_LOG_ERR("Null parameter\n");
		return -EINVAL;
	}

	dlb2 = dlb2_pmd_priv(dev);

	if (ev_port_id >= DLB2_MAX_NUM_PORTS)
		return -EINVAL;

	if (port_conf->dequeue_depth >
		evdev_dlb2_default_info.max_event_port_dequeue_depth ||
	    port_conf->enqueue_depth >
		evdev_dlb2_default_info.max_event_port_enqueue_depth)
		return -EINVAL;

	ev_port = &dlb2->ev_ports[ev_port_id];
	/* configured? */
	if (ev_port->setup_done) {
		DLB2_LOG_ERR("evport %d is already configured\n", ev_port_id);
		return -EINVAL;
	}

	ev_port->qm_port.is_directed = port_conf->event_port_cfg &
		RTE_EVENT_PORT_CFG_SINGLE_LINK;

	if (!ev_port->qm_port.is_directed) {
		ret = dlb2_hw_create_ldb_port(dlb2,
					      ev_port,
					      port_conf->dequeue_depth,
					      port_conf->enqueue_depth);
		if (ret < 0) {
			DLB2_LOG_ERR("Failed to create the lB port ve portId=%d\n",
				     ev_port_id);

			return ret;
		}
	} else {
		ret = dlb2_hw_create_dir_port(dlb2,
					      ev_port,
					      port_conf->dequeue_depth,
					      port_conf->enqueue_depth);
		if (ret < 0) {
			DLB2_LOG_ERR("Failed to create the DIR port\n");
			return ret;
		}
	}

	/* Save off port config for reconfig */
	ev_port->conf = *port_conf;

	ev_port->id = ev_port_id;
	ev_port->enq_configured = true;
	ev_port->setup_done = true;
	ev_port->inflight_max = port_conf->new_event_threshold;
	ev_port->implicit_release = !(port_conf->event_port_cfg &
		  RTE_EVENT_PORT_CFG_DISABLE_IMPL_REL);
	ev_port->outstanding_releases = 0;
	ev_port->inflight_credits = 0;
	ev_port->credit_update_quanta = RTE_LIBRTE_PMD_DLB2_SW_CREDIT_QUANTA;
	ev_port->dlb2 = dlb2; /* reverse link */

	/* Tear down pre-existing port->queue links */
	if (dlb2->run_state == DLB2_RUN_STATE_STOPPED)
		dlb2_port_link_teardown(dlb2, &dlb2->ev_ports[ev_port_id]);

	dev->data->ports[ev_port_id] = &dlb2->ev_ports[ev_port_id];

	return 0;
}

static int16_t
dlb2_hw_map_ldb_qid_to_port(struct dlb2_hw_dev *handle,
			    uint32_t qm_port_id,
			    uint16_t qm_qid,
			    uint8_t priority)
{
	struct dlb2_map_qid_args cfg;
	int32_t ret;

	if (handle == NULL)
		return -EINVAL;

	/* Build message */
	cfg.port_id = qm_port_id;
	cfg.qid = qm_qid;
	cfg.priority = EV_TO_DLB2_PRIO(priority);

	ret = dlb2_iface_map_qid(handle, &cfg);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: map qid error, ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		DLB2_LOG_ERR("dlb2: grp=%d, qm_port=%d, qm_qid=%d prio=%d\n",
			     handle->domain_id, cfg.port_id,
			     cfg.qid,
			     cfg.priority);
	} else {
		DLB2_LOG_DBG("dlb2: mapped queue %d to qm_port %d\n",
			     qm_qid, qm_port_id);
	}

	return ret;
}

static int
dlb2_event_queue_join_ldb(struct dlb2_eventdev *dlb2,
			  struct dlb2_eventdev_port *ev_port,
			  struct dlb2_eventdev_queue *ev_queue,
			  uint8_t priority)
{
	int first_avail = -1;
	int ret, i;

	for (i = 0; i < DLB2_MAX_NUM_QIDS_PER_LDB_CQ; i++) {
		if (ev_port->link[i].valid) {
			if (ev_port->link[i].queue_id == ev_queue->id &&
			    ev_port->link[i].priority == priority) {
				if (ev_port->link[i].mapped)
					return 0; /* already mapped */
				first_avail = i;
			}
		} else if (first_avail == -1)
			first_avail = i;
	}
	if (first_avail == -1) {
		DLB2_LOG_ERR("dlb2: qm_port %d has no available QID slots.\n",
			     ev_port->qm_port.id);
		return -EINVAL;
	}

	ret = dlb2_hw_map_ldb_qid_to_port(&dlb2->qm_instance,
					  ev_port->qm_port.id,
					  ev_queue->qm_queue.id,
					  priority);

	if (!ret)
		ev_port->link[first_avail].mapped = true;

	return ret;
}

static int32_t
dlb2_hw_create_dir_queue(struct dlb2_eventdev *dlb2,
			 struct dlb2_eventdev_queue *ev_queue,
			 int32_t qm_port_id)
{
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_create_dir_queue_args cfg;
	int32_t ret;

	/* The directed port is always configured before its queue */
	cfg.port_id = qm_port_id;

	if (ev_queue->depth_threshold == 0) {
		cfg.depth_threshold = RTE_PMD_DLB2_DEFAULT_DEPTH_THRESH;
		ev_queue->depth_threshold = RTE_PMD_DLB2_DEFAULT_DEPTH_THRESH;
	} else
		cfg.depth_threshold = ev_queue->depth_threshold;

	ret = dlb2_iface_dir_queue_create(handle, &cfg);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: create DIR event queue error, ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		return -EINVAL;
	}

	return cfg.response.id;
}

static int
dlb2_eventdev_dir_queue_setup(struct dlb2_eventdev *dlb2,
			      struct dlb2_eventdev_queue *ev_queue,
			      struct dlb2_eventdev_port *ev_port)
{
	int32_t qm_qid;

	qm_qid = dlb2_hw_create_dir_queue(dlb2, ev_queue, ev_port->qm_port.id);

	if (qm_qid < 0) {
		DLB2_LOG_ERR("Failed to create the DIR queue\n");
		return qm_qid;
	}

	dlb2->qm_dir_to_ev_queue_id[qm_qid] = ev_queue->id;

	ev_queue->qm_queue.id = qm_qid;

	return 0;
}

static int
dlb2_do_port_link(struct rte_eventdev *dev,
		  struct dlb2_eventdev_queue *ev_queue,
		  struct dlb2_eventdev_port *ev_port,
		  uint8_t prio)
{
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);
	int err;

	/* Don't link until start time. */
	if (dlb2->run_state == DLB2_RUN_STATE_STOPPED)
		return 0;

	if (ev_queue->qm_queue.is_directed)
		err = dlb2_eventdev_dir_queue_setup(dlb2, ev_queue, ev_port);
	else
		err = dlb2_event_queue_join_ldb(dlb2, ev_port, ev_queue, prio);

	if (err) {
		DLB2_LOG_ERR("port link failure for %s ev_q %d, ev_port %d\n",
			     ev_queue->qm_queue.is_directed ? "DIR" : "LDB",
			     ev_queue->id, ev_port->id);

		rte_errno = err;
		return -1;
	}

	return 0;
}

static int
dlb2_validate_port_link(struct dlb2_eventdev_port *ev_port,
			uint8_t queue_id,
			bool link_exists,
			int index)
{
	struct dlb2_eventdev *dlb2 = ev_port->dlb2;
	struct dlb2_eventdev_queue *ev_queue;
	bool port_is_dir, queue_is_dir;

	if (queue_id > dlb2->num_queues) {
		rte_errno = -EINVAL;
		return -1;
	}

	ev_queue = &dlb2->ev_queues[queue_id];

	if (!ev_queue->setup_done &&
	    ev_queue->qm_queue.config_state != DLB2_PREV_CONFIGURED) {
		rte_errno = -EINVAL;
		return -1;
	}

	port_is_dir = ev_port->qm_port.is_directed;
	queue_is_dir = ev_queue->qm_queue.is_directed;

	if (port_is_dir != queue_is_dir) {
		DLB2_LOG_ERR("%s queue %u can't link to %s port %u\n",
			     queue_is_dir ? "DIR" : "LDB", ev_queue->id,
			     port_is_dir ? "DIR" : "LDB", ev_port->id);

		rte_errno = -EINVAL;
		return -1;
	}

	/* Check if there is space for the requested link */
	if (!link_exists && index == -1) {
		DLB2_LOG_ERR("no space for new link\n");
		rte_errno = -ENOSPC;
		return -1;
	}

	/* Check if the directed port is already linked */
	if (ev_port->qm_port.is_directed && ev_port->num_links > 0 &&
	    !link_exists) {
		DLB2_LOG_ERR("Can't link DIR port %d to >1 queues\n",
			     ev_port->id);
		rte_errno = -EINVAL;
		return -1;
	}

	/* Check if the directed queue is already linked */
	if (ev_queue->qm_queue.is_directed && ev_queue->num_links > 0 &&
	    !link_exists) {
		DLB2_LOG_ERR("Can't link DIR queue %d to >1 ports\n",
			     ev_queue->id);
		rte_errno = -EINVAL;
		return -1;
	}

	return 0;
}

static int
dlb2_eventdev_port_link(struct rte_eventdev *dev, void *event_port,
			const uint8_t queues[], const uint8_t priorities[],
			uint16_t nb_links)

{
	struct dlb2_eventdev_port *ev_port = event_port;
	struct dlb2_eventdev *dlb2;
	int i, j;

	RTE_SET_USED(dev);

	if (ev_port == NULL) {
		DLB2_LOG_ERR("dlb2: evport not setup\n");
		rte_errno = -EINVAL;
		return 0;
	}

	if (!ev_port->setup_done &&
	    ev_port->qm_port.config_state != DLB2_PREV_CONFIGURED) {
		DLB2_LOG_ERR("dlb2: evport not setup\n");
		rte_errno = -EINVAL;
		return 0;
	}

	/* Note: rte_event_port_link() ensures the PMD won't receive a NULL
	 * queues pointer.
	 */
	if (nb_links == 0) {
		DLB2_LOG_DBG("dlb2: nb_links is 0\n");
		return 0; /* Ignore and return success */
	}

	dlb2 = ev_port->dlb2;

	DLB2_LOG_DBG("Linking %u queues to %s port %d\n",
		     nb_links,
		     ev_port->qm_port.is_directed ? "DIR" : "LDB",
		     ev_port->id);

	for (i = 0; i < nb_links; i++) {
		struct dlb2_eventdev_queue *ev_queue;
		uint8_t queue_id, prio;
		bool found = false;
		int index = -1;

		queue_id = queues[i];
		prio = priorities[i];

		/* Check if the link already exists. */
		for (j = 0; j < DLB2_MAX_NUM_QIDS_PER_LDB_CQ; j++)
			if (ev_port->link[j].valid) {
				if (ev_port->link[j].queue_id == queue_id) {
					found = true;
					index = j;
					break;
				}
			} else if (index == -1) {
				index = j;
			}

		/* could not link */
		if (index == -1)
			break;

		/* Check if already linked at the requested priority */
		if (found && ev_port->link[j].priority == prio)
			continue;

		if (dlb2_validate_port_link(ev_port, queue_id, found, index))
			break; /* return index of offending queue */

		ev_queue = &dlb2->ev_queues[queue_id];

		if (dlb2_do_port_link(dev, ev_queue, ev_port, prio))
			break; /* return index of offending queue */

		ev_queue->num_links++;

		ev_port->link[index].queue_id = queue_id;
		ev_port->link[index].priority = prio;
		ev_port->link[index].valid = true;
		/* Entry already exists?  If so, then must be prio change */
		if (!found)
			ev_port->num_links++;
	}
	return i;
}

static int16_t
dlb2_hw_unmap_ldb_qid_from_port(struct dlb2_hw_dev *handle,
				uint32_t qm_port_id,
				uint16_t qm_qid)
{
	struct dlb2_unmap_qid_args cfg;
	int32_t ret;

	if (handle == NULL)
		return -EINVAL;

	cfg.port_id = qm_port_id;
	cfg.qid = qm_qid;

	ret = dlb2_iface_unmap_qid(handle, &cfg);
	if (ret < 0)
		DLB2_LOG_ERR("dlb2: unmap qid error, ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);

	return ret;
}

static int
dlb2_event_queue_detach_ldb(struct dlb2_eventdev *dlb2,
			    struct dlb2_eventdev_port *ev_port,
			    struct dlb2_eventdev_queue *ev_queue)
{
	int ret, i;

	/* Don't unlink until start time. */
	if (dlb2->run_state == DLB2_RUN_STATE_STOPPED)
		return 0;

	for (i = 0; i < DLB2_MAX_NUM_QIDS_PER_LDB_CQ; i++) {
		if (ev_port->link[i].valid &&
		    ev_port->link[i].queue_id == ev_queue->id)
			break; /* found */
	}

	/* This is expected with eventdev API!
	 * It blindly attemmpts to unmap all queues.
	 */
	if (i == DLB2_MAX_NUM_QIDS_PER_LDB_CQ) {
		DLB2_LOG_DBG("dlb2: ignoring LB QID %d not mapped for qm_port %d.\n",
			     ev_queue->qm_queue.id,
			     ev_port->qm_port.id);
		return 0;
	}

	ret = dlb2_hw_unmap_ldb_qid_from_port(&dlb2->qm_instance,
					      ev_port->qm_port.id,
					      ev_queue->qm_queue.id);
	if (!ret)
		ev_port->link[i].mapped = false;

	return ret;
}

static int
dlb2_eventdev_port_unlink(struct rte_eventdev *dev, void *event_port,
			  uint8_t queues[], uint16_t nb_unlinks)
{
	struct dlb2_eventdev_port *ev_port = event_port;
	struct dlb2_eventdev *dlb2;
	int i;

	RTE_SET_USED(dev);

	if (!ev_port->setup_done) {
		DLB2_LOG_ERR("dlb2: evport %d is not configured\n",
			     ev_port->id);
		rte_errno = -EINVAL;
		return 0;
	}

	if (queues == NULL || nb_unlinks == 0) {
		DLB2_LOG_DBG("dlb2: queues is NULL or nb_unlinks is 0\n");
		return 0; /* Ignore and return success */
	}

	/* FIXME: How to handle unlink on a directed port? */
	if (ev_port->qm_port.is_directed) {
		DLB2_LOG_DBG("dlb2: ignore unlink from dir port %d\n",
			     ev_port->id);
		rte_errno = 0;
		return nb_unlinks; /* as if success */
	}

	dlb2 = ev_port->dlb2;

	for (i = 0; i < nb_unlinks; i++) {
		struct dlb2_eventdev_queue *ev_queue;
		int ret, j;

		if (queues[i] >= dlb2->num_queues) {
			DLB2_LOG_ERR("dlb2: invalid queue id %d\n", queues[i]);
			rte_errno = -EINVAL;
			return i; /* return index of offending queue */
		}

		ev_queue = &dlb2->ev_queues[queues[i]];

		/* Does a link exist? */
		for (j = 0; j < DLB2_MAX_NUM_QIDS_PER_LDB_CQ; j++)
			if (ev_port->link[j].queue_id == queues[i] &&
			    ev_port->link[j].valid)
				break;

		if (j == DLB2_MAX_NUM_QIDS_PER_LDB_CQ)
			continue;

		ret = dlb2_event_queue_detach_ldb(dlb2, ev_port, ev_queue);
		if (ret) {
			DLB2_LOG_ERR("unlink err=%d for port %d queue %d\n",
				     ret, ev_port->id, queues[i]);
			rte_errno = -ENOENT;
			return i; /* return index of offending queue */
		}

		ev_port->link[j].valid = false;
		ev_port->num_links--;
		ev_queue->num_links--;
	}

	return nb_unlinks;
}

static int
dlb2_eventdev_port_unlinks_in_progress(struct rte_eventdev *dev,
				       void *event_port)
{
	struct dlb2_eventdev_port *ev_port = event_port;
	struct dlb2_eventdev *dlb2;
	struct dlb2_hw_dev *handle;
	struct dlb2_pending_port_unmaps_args cfg;
	int ret;

	RTE_SET_USED(dev);

	if (!ev_port->setup_done) {
		DLB2_LOG_ERR("dlb2: evport %d is not configured\n",
			     ev_port->id);
		rte_errno = -EINVAL;
		return 0;
	}

	cfg.port_id = ev_port->qm_port.id;
	dlb2 = ev_port->dlb2;
	handle = &dlb2->qm_instance;
	ret = dlb2_iface_pending_port_unmaps(handle, &cfg);

	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: num_unlinks_in_progress ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		return ret;
	}

	return cfg.response.id;
}

static int
dlb2_eventdev_reapply_configuration(struct rte_eventdev *dev)
{
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);
	int ret, i;

	/* If an event queue or port was previously configured, but hasn't been
	 * reconfigured, reapply its original configuration.
	 */
	for (i = 0; i < dlb2->num_queues; i++) {
		struct dlb2_eventdev_queue *ev_queue;

		ev_queue = &dlb2->ev_queues[i];

		if (ev_queue->qm_queue.config_state != DLB2_PREV_CONFIGURED)
			continue;

		ret = dlb2_eventdev_queue_setup(dev, i, &ev_queue->conf);
		if (ret < 0) {
			DLB2_LOG_ERR("dlb2: failed to reconfigure queue %d", i);
			return ret;
		}
	}

	for (i = 0; i < dlb2->num_ports; i++) {
		struct dlb2_eventdev_port *ev_port = &dlb2->ev_ports[i];

		if (ev_port->qm_port.config_state != DLB2_PREV_CONFIGURED)
			continue;

		ret = dlb2_eventdev_port_setup(dev, i, &ev_port->conf);
		if (ret < 0) {
			DLB2_LOG_ERR("dlb2: failed to reconfigure ev_port %d",
				     i);
			return ret;
		}
	}

	return 0;
}

static int
dlb2_eventdev_apply_port_links(struct rte_eventdev *dev)
{
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);
	int i;

	/* Perform requested port->queue links */
	for (i = 0; i < dlb2->num_ports; i++) {
		struct dlb2_eventdev_port *ev_port = &dlb2->ev_ports[i];
		int j;

		for (j = 0; j < DLB2_MAX_NUM_QIDS_PER_LDB_CQ; j++) {
			struct dlb2_eventdev_queue *ev_queue;
			uint8_t prio, queue_id;

			if (!ev_port->link[j].valid)
				continue;

			prio = ev_port->link[j].priority;
			queue_id = ev_port->link[j].queue_id;

			if (dlb2_validate_port_link(ev_port, queue_id, true, j))
				return -EINVAL;

			ev_queue = &dlb2->ev_queues[queue_id];

			if (dlb2_do_port_link(dev, ev_queue, ev_port, prio))
				return -EINVAL;
		}
	}

	return 0;
}

static int
dlb2_eventdev_start(struct rte_eventdev *dev)
{
	struct dlb2_eventdev *dlb2 = dlb2_pmd_priv(dev);
	struct dlb2_hw_dev *handle = &dlb2->qm_instance;
	struct dlb2_start_domain_args cfg;
	int ret, i;

	rte_spinlock_lock(&dlb2->qm_instance.resource_lock);
	if (dlb2->run_state != DLB2_RUN_STATE_STOPPED) {
		DLB2_LOG_ERR("bad state %d for dev_start\n",
			     (int)dlb2->run_state);
		rte_spinlock_unlock(&dlb2->qm_instance.resource_lock);
		return -EINVAL;
	}
	dlb2->run_state = DLB2_RUN_STATE_STARTING;
	rte_spinlock_unlock(&dlb2->qm_instance.resource_lock);

	/* If the device was configured more than once, some event ports and/or
	 * queues may need to be reconfigured.
	 */
	ret = dlb2_eventdev_reapply_configuration(dev);
	if (ret)
		return ret;

	/* The DLB PMD delays port links until the device is started. */
	ret = dlb2_eventdev_apply_port_links(dev);
	if (ret)
		return ret;

	for (i = 0; i < dlb2->num_ports; i++) {
		if (!dlb2->ev_ports[i].setup_done) {
			DLB2_LOG_ERR("dlb2: port %d not setup", i);
			return -ESTALE;
		}
	}

	for (i = 0; i < dlb2->num_queues; i++) {
		if (dlb2->ev_queues[i].num_links == 0) {
			DLB2_LOG_ERR("dlb2: queue %d is not linked", i);
			return -ENOLINK;
		}
	}

	ret = dlb2_iface_sched_domain_start(handle, &cfg);
	if (ret < 0) {
		DLB2_LOG_ERR("dlb2: sched_domain_start ret=%d (driver status: %s)\n",
			     ret, dlb2_error_strings[cfg.response.status]);
		return ret;
	}

	dlb2->run_state = DLB2_RUN_STATE_STARTED;
	DLB2_LOG_DBG("dlb2: sched_domain_start completed OK\n");

	return 0;
}

static void
dlb2_entry_points_init(struct rte_eventdev *dev)
{
	/* Expose PMD's eventdev interface */
	static struct rte_eventdev_ops dlb2_eventdev_entry_ops = {
		.dev_infos_get    = dlb2_eventdev_info_get,
		.dev_configure    = dlb2_eventdev_configure,
		.dev_start        = dlb2_eventdev_start,
		.queue_def_conf   = dlb2_eventdev_queue_default_conf_get,
		.queue_setup      = dlb2_eventdev_queue_setup,
		.port_def_conf    = dlb2_eventdev_port_default_conf_get,
		.port_setup       = dlb2_eventdev_port_setup,
		.port_link        = dlb2_eventdev_port_link,
		.port_unlink      = dlb2_eventdev_port_unlink,
		.port_unlinks_in_progress =
				    dlb2_eventdev_port_unlinks_in_progress,
		.dump             = dlb2_eventdev_dump,
		.xstats_get       = dlb2_eventdev_xstats_get,
		.xstats_get_names = dlb2_eventdev_xstats_get_names,
		.xstats_get_by_name = dlb2_eventdev_xstats_get_by_name,
		.xstats_reset	    = dlb2_eventdev_xstats_reset,
	};

	dev->dev_ops = &dlb2_eventdev_entry_ops;
}

int
dlb2_primary_eventdev_probe(struct rte_eventdev *dev,
			    const char *name,
			    struct dlb2_devargs *dlb2_args)
{
	struct dlb2_eventdev *dlb2;
	int err;

	dlb2 = dev->data->dev_private;

	dlb2->event_dev = dev; /* backlink */

	evdev_dlb2_default_info.driver_name = name;

	dlb2->max_num_events_override = dlb2_args->max_num_events;
	dlb2->num_dir_credits_override = dlb2_args->num_dir_credits_override;
	dlb2->qm_instance.cos_id = dlb2_args->cos_id;

	err = dlb2_iface_open(&dlb2->qm_instance, name);
	if (err < 0) {
		DLB2_LOG_ERR("could not open event hardware device, err=%d\n",
			     err);
		return err;
	}

	err = dlb2_iface_get_device_version(&dlb2->qm_instance,
					    &dlb2->revision);
	if (err < 0) {
		DLB2_LOG_ERR("dlb2: failed to get the device version, err=%d\n",
			     err);
		return err;
	}

	err = dlb2_hw_query_resources(dlb2);
	if (err) {
		DLB2_LOG_ERR("get resources err=%d for %s\n",
			     err, name);
		return err;
	}

	dlb2_iface_hardware_init(&dlb2->qm_instance);

	err = dlb2_iface_get_cq_poll_mode(&dlb2->qm_instance, &dlb2->poll_mode);
	if (err < 0) {
		DLB2_LOG_ERR("dlb2: failed to get the poll mode, err=%d\n",
			     err);
		return err;
	}

	/* Complete xtstats runtime initialization */
	err = dlb2_xstats_init(dlb2);
	if (err) {
		DLB2_LOG_ERR("dlb2: failed to init xstats, err=%d\n", err);
		return err;
	}

	rte_spinlock_init(&dlb2->qm_instance.resource_lock);

	dlb2_iface_low_level_io_init();

	dlb2_entry_points_init(dev);

	dlb2_init_queue_depth_thresholds(dlb2,
					 dlb2_args->qid_depth_thresholds.val);

	return 0;
}

int
dlb2_secondary_eventdev_probe(struct rte_eventdev *dev,
			      const char *name)
{
	struct dlb2_eventdev *dlb2;
	int err;

	dlb2 = dev->data->dev_private;

	evdev_dlb2_default_info.driver_name = name;

	err = dlb2_iface_open(&dlb2->qm_instance, name);
	if (err < 0) {
		DLB2_LOG_ERR("could not open event hardware device, err=%d\n",
			     err);
		return err;
	}

	err = dlb2_hw_query_resources(dlb2);
	if (err) {
		DLB2_LOG_ERR("get resources err=%d for %s\n",
			     err, name);
		return err;
	}

	dlb2_iface_low_level_io_init();

	dlb2_entry_points_init(dev);

	return 0;
}

int
dlb2_parse_params(const char *params,
		  const char *name,
		  struct dlb2_devargs *dlb2_args)
{
	int ret = 0;
	static const char * const args[] = { NUMA_NODE_ARG,
					     DLB2_MAX_NUM_EVENTS,
					     DLB2_NUM_DIR_CREDITS,
					     DEV_ID_ARG,
					     DLB2_QID_DEPTH_THRESH_ARG,
					     DLB2_COS_ARG,
					     NULL };

	if (params != NULL && params[0] != '\0') {
		struct rte_kvargs *kvlist = rte_kvargs_parse(params, args);

		if (kvlist == NULL) {
			RTE_LOG(INFO, PMD,
				"Ignoring unsupported parameters when creating device '%s'\n",
				name);
		} else {
			int ret = rte_kvargs_process(kvlist, NUMA_NODE_ARG,
						     set_numa_node,
						     &dlb2_args->socket_id);
			if (ret != 0) {
				DLB2_LOG_ERR("%s: Error parsing numa node parameter",
					     name);
				rte_kvargs_free(kvlist);
				return ret;
			}

			ret = rte_kvargs_process(kvlist, DLB2_MAX_NUM_EVENTS,
						 set_max_num_events,
						 &dlb2_args->max_num_events);
			if (ret != 0) {
				DLB2_LOG_ERR("%s: Error parsing max_num_events parameter",
					     name);
				rte_kvargs_free(kvlist);
				return ret;
			}

			ret = rte_kvargs_process(kvlist,
					DLB2_NUM_DIR_CREDITS,
					set_num_dir_credits,
					&dlb2_args->num_dir_credits_override);
			if (ret != 0) {
				DLB2_LOG_ERR("%s: Error parsing num_dir_credits parameter",
					     name);
				rte_kvargs_free(kvlist);
				return ret;
			}

			ret = rte_kvargs_process(kvlist, DEV_ID_ARG,
						 set_dev_id,
						 &dlb2_args->dev_id);
			if (ret != 0) {
				DLB2_LOG_ERR("%s: Error parsing dev_id parameter",
					     name);
				rte_kvargs_free(kvlist);
				return ret;
			}

			ret = rte_kvargs_process(
					kvlist,
					DLB2_QID_DEPTH_THRESH_ARG,
					set_qid_depth_thresh,
					&dlb2_args->qid_depth_thresholds);
			if (ret != 0) {
				DLB2_LOG_ERR("%s: Error parsing qid_depth_thresh parameter",
					     name);
				rte_kvargs_free(kvlist);
				return ret;
			}

			ret = rte_kvargs_process(kvlist, DLB2_COS_ARG,
						 set_cos,
						 &dlb2_args->cos_id);
			if (ret != 0) {
				DLB2_LOG_ERR("%s: Error parsing cos parameter",
					     name);
				rte_kvargs_free(kvlist);
				return ret;
			}

			rte_kvargs_free(kvlist);
		}
	}
	return ret;
}
RTE_LOG_REGISTER(eventdev_dlb2_log_level, pmd.event.dlb2, NOTICE);