/**
 * Header file for eCryptfs decision graph
 * 
 * Copyright (C) 2004-2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Trevor Highland <trevor.highland@gmail.com>
 *
 * The structs here are shared between kernel and userspace, so if you
 * are running a 64-bit kernel, you need to compile your userspace
 * applications as 64-bit binaries.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef DECISION_GRAPH_H
#define DECISION_GRAPH_H

#ifndef S_SPLINT_S
#include <stdio.h>
#endif

struct param_node;

struct val_node {
        void *val;
        struct val_node *next;
};

struct ecryptfs_ctx;

/**
 * transition_node
 * @val: If this value and the value set for the parent param_node
 *       match, then this transition_node is followed. This value is
 *       part of the transition_node's definition. For internal use
 *       only.
 * @pretty_val: The value displayed to the user.
 * @next_token: The param_node that we transition to if this
 *              transition_node is followed.
 * @trans_func: The function to execute when this transition node is
 *              followed.
 *
 * See src/libecryptfs/decision_graph.c::do_transition()
 *
 * If @val is set to NULL on definition, then this transition node
 * will be followed by default, no matter what the parent param_node's
 * val is set to.
 *
 * If @next_token is NULL, then @trans_func must be defined.
 *
 * If @trans_func is defined and returns NULL_TOK, then @next_token is
 * used as the next param_node.
 */
struct transition_node {
#define ECRYPTFS_TN_FLAG_REQ_FREE 0x00000001
	uint32_t flags;
        char *val;
        char *pretty_val;
        struct param_node *next_token;
        int (*trans_func)(struct ecryptfs_ctx *, struct param_node *,
			  struct val_node **, void **);
};

struct param_node {
#define NULL_TOK 1
#define DEFAULT_TOK 2
#define MOUNT_ERROR 3
#define WRONG_VALUE 4
        int num_mnt_opt_names;
#define MAX_NUM_MNT_OPT_NAMES 8
        char *mnt_opt_names[MAX_NUM_MNT_OPT_NAMES];
        char *prompt;
#define VAL_STR 0
#define VAL_HEX 1
        int val_type;
        char *val;
        char *default_val;
        char *suggested_val;
        void (*display_opts)(struct param_node *);
#define ECRYPTFS_PARAM_FLAG_ECHO_INPUT	   0x00000001
#define ECRYPTFS_PARAM_FLAG_MASK_OUTPUT    0x00000002
#define ECRYPTFS_ALLOW_IMPLICIT_TRANSITION 0x00000004
#define ECRYPTFS_PARAM_FLAG_NO_VALUE       0x00000008
#define DISPLAY_TRANSITION_NODE_VALS       0x00000010
#define VERIFY_VALUE			   0x00000020
#define STDIN_REQUIRED			   0x00000040
#define PARAMETER_SET			   0x00000080
#define ECRYPTFS_PARAM_FLAG_LOCK_MEM       0x00000100
#define ECRYPTFS_PARAM_FORCE_DISPLAY_NODES 0x00000200
#define ECRYPTFS_DISPLAY_PRETTY_VALS       0x00000400
#define ECRYPTFS_NO_AUTO_TRANSITION        0x00000800
#define ECRYPTFS_IMPLICIT_OVERRIDE_DEFAULT 0x00001000
#define ECRYPTFS_NONEMPTY_VALUE_REQUIRED   0x00002000
        uint32_t flags;
        int num_transitions;
#define MAX_NUM_TRANSITIONS 64
        struct transition_node tl[MAX_NUM_TRANSITIONS];
};

struct prompt_elem;

struct prompt_elem {
	char *str;
	struct prompt_elem *next;
};

int add_transition_node_to_param_node(struct param_node *param_node,
				      struct transition_node *trans_node);
void ecryptfs_dump_param_node(FILE *file_stream,
			      struct param_node *param_node, int depth,
			      int recursive);
void ecryptfs_dump_transition_node(FILE *file_stream,
				   struct transition_node *trans_node,
				   int depth, int recursive);
void ecryptfs_dump_decision_graph(FILE *file_stream,
				  struct param_node *param_node, int depth);
int ecryptfs_set_exit_param_on_graph(struct param_node *param_node,
				     struct param_node *exit_param_node);

struct ecryptfs_name_val_pair;

int ecryptfs_insert_params_in_subgraph(struct ecryptfs_name_val_pair *nvp,
				       struct transition_node *trans_node);
int eval_param_tree(struct ecryptfs_ctx *ctx, struct param_node *node,
		    struct ecryptfs_name_val_pair *nvp_head,
		    struct val_node **val_stack_head);

#endif
