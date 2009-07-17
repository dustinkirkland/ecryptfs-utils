/**
 * Copyright (C) 2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Trevor Highland <trevor.highland@gmail.com>
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

#include "config.h"
#include <errno.h>
#include <stdint.h>
#ifndef S_SPLINT_S
#include <stdio.h>
#include <syslog.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/ecryptfs.h"
#include "../include/decision_graph.h"

int stack_push(struct val_node **head, void *val)
{
	struct val_node *node = malloc(sizeof(struct val_node));
	int rc = 0;

	if (!node) {
		rc = -ENOMEM;
		goto out;
	}
	node->val = val;
	node->next = *head;
	*head = node;
out:
	return rc;
}

int stack_pop(struct val_node **head)
{
	struct val_node *tmp = (*head)->next;

	free((*head)->val);
	free(*head);
	*head = tmp;
	return 0;
}

int stack_pop_val(struct val_node **head, void **val)
{
	if (*head && val) {
		struct val_node *tmp = (*head)->next;

		*val = (*head)->val;
		free(*head);
		*head = tmp;
		return 0;
	}
	return -1;
}

int free_name_val_pairs(struct ecryptfs_name_val_pair *pair)
{
	struct ecryptfs_name_val_pair *next;

	while (pair) {
		if (pair->value)
			free(pair->value);
		if (pair->name)
			free(pair->name);
		next = pair->next;
		free(pair);
		pair = next;
	}
	return 0;
}

int add_transition_node_to_param_node(struct param_node *param_node,
				      struct transition_node *trans_node)
{
	int rc;

	if (param_node->num_transitions >= MAX_NUM_TRANSITIONS) {
		syslog(LOG_ERR, "Too many transitions on node with primary "
		       "alias [%s]\n", param_node->mnt_opt_names[0]);
		rc = -ENOMEM;
		goto out;
	}
	memcpy(&(param_node->tl[param_node->num_transitions++]),
	       trans_node, sizeof(*trans_node));
	rc = 0;
out:
	return rc;
}

/**
 * set_exit_param_node_for_node
 *
 * Sets all NULL next_token's to exit_param_node
 */
int set_exit_param_node_for_node(struct param_node *param_node,
				 struct param_node *exit_param_node,
				 int recursive)
{
	int i;
	int rc = 0;

	for (i = 0; i < param_node->num_transitions; i++)
		if (param_node->tl[i].next_token == NULL) {
			param_node->tl[i].val = "default";
			param_node->tl[i].pretty_val = "default";
			param_node->tl[i].next_token = exit_param_node;
		} else if (recursive) {
			rc = set_exit_param_node_for_node(
				param_node->tl[i].next_token,
				exit_param_node, 1);
			if (rc)
				goto out;
		}
out:
	return rc;
}

/**
 * Sets the exit param node for all NULL transitions throughout an
 * entire graph.
 */
int ecryptfs_set_exit_param_on_graph(struct param_node *param_node,
				     struct param_node *exit_param_node)
{
	return set_exit_param_node_for_node(param_node, exit_param_node, 1);
}

/**
 * set_exit_param_node_for_arr
 *
 * Sets the exit param node for all NULL transitions contained in an
 * array of param nodes.
 */
int set_exit_param_node_for_arr(struct param_node param_node_arr[],
				struct param_node *exit_param_node)
{
	int arr_len = sizeof(param_node_arr) / sizeof(param_node_arr[0]);
	int i;

	for (i = 0; i < arr_len; i++)
		set_exit_param_node_for_node(&param_node_arr[i],
					     exit_param_node, 0);
	return 0;
}

void ecryptfs_destroy_nvp(struct ecryptfs_name_val_pair *nvp)
{
	return;
}

int ecryptfs_delete_nvp(struct ecryptfs_name_val_pair *nvp_head,
			struct ecryptfs_name_val_pair *nvp)
{
	int rc = 0;

	while (nvp_head) {
		if (nvp_head->next == nvp) {
			nvp_head->next = nvp->next;
			ecryptfs_destroy_nvp(nvp);
			goto out;
		}
		nvp_head = nvp_head->next;
	}
	rc = -EINVAL;
out:
	return rc;
}

/**
 * do_transition
 * @ctx: The current eCryptfs library context
 * @next: Set to the param_node that the transition engine determines
 *        is the next node
 * @current: The current param_node from which we are transitioning
 * @nvp_head: The name-value pair list that contains name-value pairs
 *            specified on the command line or provided via the
 *            .ecryptfsrc file. Whenever a param node needs a value,
 *            the decision graph logic first scans this list for a
 *            corresponding name-value pair
 * @mnt_params: Head of mount option stack that the callback functions
 *              for the transition nodes in the param node populate
 * @foo: An arbitrary data structure that the transition node callback
 *       functions create, reference, and destroy
 *
 * This function needs to compare transition nodes to options.
 * It is currently comparing them to values provided to options.
 * i.e., each transition is an option; this is incorrect.
 */
int do_transition(struct ecryptfs_ctx *ctx, struct param_node **next,
		  struct param_node *current,
		  struct ecryptfs_name_val_pair *nvp_head,
		  struct val_node **mnt_params, void **foo)
{
	static int repeated = 0;
	static struct param_node *lastnode = NULL;
	int i, rc;

	if (current != lastnode)
		repeated = 0;

	lastnode = current;

	for (i = 0; i < current->num_transitions; i++) {
		struct transition_node *tn = &current->tl[i];
		struct ecryptfs_name_val_pair *nvp = nvp_head->next;

		if (tn->val && current->val
		    && strcmp(current->val, tn->val) == 0) {
			rc = 0;
			if (tn->trans_func) {
				rc = tn->trans_func(ctx, current,
						    mnt_params, foo);
			}
			if ((*next = tn->next_token)) {
				if (ecryptfs_verbosity) {
					syslog(LOG_INFO,
					       "Transitioning from [%p]; name "
					       "= [%s] to [%p]; name = [%s] "
					       "per transition node's "
					       "next_token\n", current,
					       current->mnt_opt_names[0],
					       (*next),
					       (*next)->mnt_opt_names[0]);
				}
				return rc;
			}
			else return EINVAL;
		}
		while (nvp) {
			int trans_func_tok_id = NULL_TOK;

			if (tn->val && strcmp(nvp->name, tn->val)) {
				nvp = nvp->next;
				continue;
			}
			if (tn->trans_func)
				trans_func_tok_id =
					tn->trans_func(ctx, current,
						       mnt_params, foo);
			if (trans_func_tok_id == MOUNT_ERROR) {
				return trans_func_tok_id;
			}
			if (trans_func_tok_id == DEFAULT_TOK) {
				if ((*next = tn->next_token))
					return 0;
				else
					return -EINVAL;
			} else if (trans_func_tok_id == NULL_TOK) {
				if ((*next = tn->next_token))
					return 0;
				else
					return -EINVAL;
			}
			nvp = nvp->next;
		}
	}
	for (i = 0; i < current->num_transitions; i++) {
		struct transition_node *tn = &current->tl[i];

		if (tn->val && strcmp("default", tn->val) == 0) {
			int trans_func_tok_id = NULL_TOK;

			if (tn->trans_func)
				trans_func_tok_id =
					tn->trans_func(ctx, current,
						       mnt_params, foo);
			if (trans_func_tok_id == WRONG_VALUE) { 
				if (ctx->verbosity || 
				    (current->flags & STDIN_REQUIRED)) {
						if (++repeated >= 5)
							return -EINVAL;
						else {
							*next = current;
							return 0;
						}
				} else 
					return -EINVAL;
			}
			if (trans_func_tok_id == MOUNT_ERROR || 
			    trans_func_tok_id < 0)
				return trans_func_tok_id;
			if ((*next = tn->next_token))
				return 0;
			else return -EINVAL;
		}
	}
	if (current->num_transitions)
		return MOUNT_ERROR;
	return NULL_TOK;
}

/**
 * Try to find one of the aliases for this node in the list of
 * name-value pairs. If found, set the value from that element in the
 * list.
 *
 * Returns non-zero on error condition
 */
static int retrieve_val(int *value_retrieved,
			struct ecryptfs_name_val_pair *nvp_head,
			struct param_node *node)
{
	int i = node->num_mnt_opt_names;
	int rc = 0;

	if (ecryptfs_verbosity)
		syslog(LOG_INFO, "%s: Called on node [%s]\n", __FUNCTION__,
		       node->mnt_opt_names[0]);
	(*value_retrieved) = 0;
	while (i > 0) {
		struct ecryptfs_name_val_pair *temp = nvp_head->next;

		i--;
		while (temp) {
			if (strcmp(temp->name, node->mnt_opt_names[i]) == 0
			    && !(temp->flags & ECRYPTFS_PROCESSED)) {
				if (ecryptfs_verbosity)
					syslog(LOG_INFO, "From param_node = "
					       "[%p]; mnt_opt_names[0] = [%s]"
					       ": Setting "
					       "ECRYPTFS_PROCESSED to nvp with "
					       "nvp->name = [%s]\n",
					       node, node->mnt_opt_names[0],
					       temp->name);
				/* Prevent the same name/value pair
				 * from being consumed twice */
				temp->flags |= ECRYPTFS_PROCESSED;
				if (temp->value
				    && (strcmp(temp->value, "(null)") != 0)) {
					if (asprintf(&node->val, "%s",
						     temp->value) == -1) {
						rc = -ENOMEM;
						goto out;
					}
				} else
					node->flags |= PARAMETER_SET;
				(*value_retrieved) = 1;
				goto out;
			}
			temp = temp->next;
		}
	}
	if (node->default_val && (strcmp(node->default_val, "NULL") != 0)) {
		if (asprintf(&node->val, "%s", node->default_val) == -1) {
			rc = -ENOMEM;
			goto out;
		}
		if (ecryptfs_verbosity)
			syslog(LOG_INFO, "%s: Value retrieved from "
			       "node->default_val = [%s]\n", __FUNCTION__,
			       node->default_val);
		(*value_retrieved) = 1;
		goto out;
	}
out:
	return rc;
}

/**
 * This function can prompt the user and/or check some list of values
 * to get what it needs. Caller must free node->val if it winds up
 * being non-NULL.
 */
static int alloc_and_get_val(struct ecryptfs_ctx *ctx, struct param_node *node,
			     struct ecryptfs_name_val_pair *nvp_head)
{
	char *verify_prompt;
	char *verify;
	int val;
	int value_retrieved;
	int i;
	int rc = 0;
	int tries = 0;

	if (ecryptfs_verbosity)
		syslog(LOG_INFO, "%s: Called on node->mnt_opt_names[0] = [%s]",
		       __FUNCTION__, node->mnt_opt_names[0]);
	if (node->val) {
		if (ecryptfs_verbosity)
			syslog(LOG_INFO, "%s: node->val already set to [%s]\n",
			       __FUNCTION__, node->val);
		goto out;
	}
	rc = retrieve_val(&value_retrieved, nvp_head, node);
	if (rc) {
		syslog(LOG_ERR, "%s: Error attempting to retrieve value; "
		       "rc = [%d]\n", __FUNCTION__, rc);
		goto out;
	}
	if (value_retrieved) {
		if (ecryptfs_verbosity)
			syslog(LOG_INFO,
			       "%s: Value retrieved from default_val or from "
			       "parameter list; returning\n",
			       __FUNCTION__);
		if (!(node->flags & ECRYPTFS_ALLOW_IMPLICIT_TRANSITION
		      && node->flags & ECRYPTFS_IMPLICIT_OVERRIDE_DEFAULT))
			goto out;
	}
	if (node->flags & ECRYPTFS_ALLOW_IMPLICIT_TRANSITION
	    && !(node->flags & ECRYPTFS_NO_AUTO_TRANSITION)) {
		for (i = 0; i < node->num_transitions; i++) {
			if (node->tl[i].next_token)
				rc = retrieve_val(&value_retrieved, nvp_head,
						  node->tl[i].next_token);
			if (rc) {
				syslog(LOG_ERR, "%s: Error attempting to "
				       "retrieve value; rc = [%d]\n",
				       __FUNCTION__, rc);
				goto out;
			}
			if (value_retrieved) {
				if (ecryptfs_verbosity)
					syslog(LOG_INFO,
					       "%s: Value retrieved from "
					       "default_val or from parameter "
					       "list for successive "
					       "node at transition slot [%d]; "
					       "returning\n", __FUNCTION__, i);
				rc = asprintf(&node->val, "%s",
					      node->tl[i].next_token->mnt_opt_names[0]);
				if (rc == -1) {
					rc = -ENOMEM;
					goto out;
				}
				rc = 0;
				goto out;
			}
		}
	}
	if (node->flags & ECRYPTFS_PARAM_FLAG_NO_VALUE) {
		if (ecryptfs_verbosity)
			syslog(LOG_INFO,
			       "%s: ECRYPTFS_PARAM_FLAG_NO_VALUE set\n",
			       __FUNCTION__);
		goto out;
	}
	if (ctx->verbosity == 0 && !(node->flags & STDIN_REQUIRED)) {
		if (ecryptfs_verbosity)
			syslog(LOG_INFO, "%s: ctx->verbosity == 0 and "
			       "STDIN_REQUIRED not set\n", __FUNCTION__);
		goto out;
	}
	if ((node->flags & PARAMETER_SET) && !(node->flags & STDIN_REQUIRED)) {
		if (ecryptfs_verbosity)
			syslog(LOG_INFO, "%s: PARAMETER_SET and "
			       "STDIN_REQUIRED not set\n", __FUNCTION__);
		goto out;
	}
	if (ctx->get_string) {
		if (ecryptfs_verbosity)
			syslog(LOG_INFO, "%s: ctx->get_string defined\n",
			       __FUNCTION__);
		if (node->flags & DISPLAY_TRANSITION_NODE_VALS) {
			struct prompt_elem pe_head;
			struct prompt_elem *pe;
			char *prompt;
			uint32_t prompt_len;
			int i;

			if (ecryptfs_verbosity)
				syslog(LOG_INFO, "%s: DISPLAY_TRANSITION_NODE_"
				       "VALS set\n", __FUNCTION__);
			memset(&pe_head, 0, sizeof(pe_head));
			pe = &pe_head;
			if ((node->num_transitions == 1)
			    && !(node->flags
				 & ECRYPTFS_PARAM_FORCE_DISPLAY_NODES)) {
				if (asprintf(&(node->val), "%s",
					     node->tl[0].val) == -1) {
					rc = -ENOMEM;
					goto out;
				}
				rc = 0;
				goto out;
			}
			pe->next = malloc(sizeof(*pe));
			if (!pe->next) {
				rc = -ENOMEM;
				goto out;
			}
			pe = pe->next;
			memset(pe, 0, sizeof(*pe));
			rc = asprintf(&pe->str, "%s: \n", node->prompt);
			if (rc == -1) {
				rc = -ENOMEM;
				goto out;
			}
			rc = 0;
			for (i = 0; i < node->num_transitions; i++) {
				pe->next = malloc(sizeof(*pe));
				if (!pe->next) {
					rc = -ENOMEM;
					goto out;
				}
				pe = pe->next;
				memset(pe, 0, sizeof(*pe));
				if (node->flags & ECRYPTFS_DISPLAY_PRETTY_VALS)
					rc = asprintf(&pe->str, " %d) %s\n",
						      (i + 1),
						      node->tl[i].pretty_val);
				else
					rc = asprintf(&pe->str, " %d) %s\n",
						      (i + 1),
						      node->tl[i].val);
				if (rc == -1) {
					rc = -ENOMEM;
					goto out;
				}
				rc = 0;
			}
			pe->next = malloc(sizeof(*pe));
			if (!pe->next) {
				rc = -ENOMEM;
				goto out;
			}
			pe = pe->next;
			memset(pe, 0, sizeof(*pe));
			if (node->suggested_val)
				rc = asprintf(&pe->str, "Selection [%s]",
					      node->suggested_val);
			else if (node->default_val)
				rc = asprintf(&pe->str, "Selection [%s]",
					      node->default_val);
			else
				rc = asprintf(&pe->str, "Selection");
			if (rc == -1) {
				rc = -ENOMEM;
				goto out;
			}
			rc = 0;
			/* Convert prompt_elem linked list into
			 * single prompt string */
			prompt_len = 0;
			pe = pe_head.next;
			while (pe) {
				prompt_len += strlen(pe->str);
				pe = pe->next;
			}
			prompt_len++;
			i = 0;
			prompt = malloc(prompt_len);
			if (!prompt) {
				rc = -ENOMEM;
				goto out;
			}
			pe = pe_head.next;
			while (pe) {
				struct prompt_elem *pe_tmp;

				memcpy(&prompt[i], pe->str, strlen(pe->str));
				i += strlen(pe->str);
				pe_tmp = pe;
				pe = pe->next;
				free(pe_tmp->str);
				free(pe_tmp);
			}
			prompt[i] = '\0';
get_value:
			if ((rc = (ctx->get_string)
				      (&(node->val), prompt,
					(node->flags
					  & ECRYPTFS_PARAM_FLAG_ECHO_INPUT)))) {
				free(prompt);
				return rc;
			}
			val = atoi(node->val);
			if (val > 0 && val <= node->num_transitions) {
				free(node->val);
				if (asprintf(&(node->val), "%s",
					     node->tl[val - 1].val) == -1) {
					rc = -ENOMEM;
					goto out;
				}
			} else {
				int valid_val;

				if (node->val[0] == '\0') {
					if (!node->suggested_val)
						goto get_value;
					rc = asprintf(&node->val, "%s",
						      node->suggested_val);
					if (rc == -1) {
						rc = -ENOMEM;
						goto out;
					}
					rc = 0;
				}
				valid_val = 0;
				for (i = 0; i < node->num_transitions; i++) {
					if (strcmp(node->val, node->tl[i].val)
					    == 0) {
						valid_val = 1;
						break;
					}
				}
				if (!valid_val)
					goto get_value;
			}
			free(prompt);
			return rc;
		} else {
			char *prompt;

			if (ecryptfs_verbosity)
				syslog(LOG_INFO, "%s: DISPLAY_TRANSITION_NODE_"
				       "VALS not set\n", __FUNCTION__);
obtain_value:
			if (++tries > 3) return EINVAL;
			if (node->suggested_val)
				rc = asprintf(&prompt, "%s [%s]", node->prompt,
					 node->suggested_val);
			else
				rc = asprintf(&prompt, "%s", node->prompt);
			if (rc == -1) {
				rc = -ENOMEM;
				goto out;
			}
			rc = 0;
			if (ecryptfs_verbosity)
				syslog(LOG_INFO,
				       "%s: node->mnt_opt_names[0] = [%s]\n; "
				       "node->flags = [0x%.8x]\n",
				       __FUNCTION__,
				       node->mnt_opt_names[0], node->flags);
			rc = (ctx->get_string)
				(&(node->val), prompt,
				 (node->flags
				  & ECRYPTFS_PARAM_FLAG_ECHO_INPUT));
			free(prompt);
			if (rc)
				goto out;
			if (node->val[0] == '\0' && 
			    (node->flags & ECRYPTFS_NONEMPTY_VALUE_REQUIRED)) {
				fprintf(stderr,"Wrong input, non-empty value "
					"required!\n");
				goto obtain_value;
			}
			if (node->flags & VERIFY_VALUE) {
				rc = asprintf(&verify_prompt, "Verify %s",
					      node->prompt);
				if (rc == -1)
					return -ENOMEM;
				rc = (ctx->get_string)
					(&verify, verify_prompt,
					 (node->flags
					  & ECRYPTFS_PARAM_FLAG_ECHO_INPUT));
				free(verify_prompt);
				if (rc)
					return -EIO;
				rc = strcmp(verify, node->val); 
				free(verify);
				if (rc) {
					free(node->val);
					node->val = NULL;
					goto obtain_value;
				}
			}
			if (node->val[0] == '\0') {
				free(node->val);
				node->val = node->suggested_val;
			}
			return rc;
		}
	} else {
		if (ecryptfs_verbosity)
			syslog(LOG_INFO, "%s: ctx->get_string not defined",
			       __FUNCTION__);
	}
	rc = MOUNT_ERROR;
out:
	return rc;
}

static void get_verbosity(struct ecryptfs_name_val_pair *nvp_head,
			  int *verbosity)
{
	struct ecryptfs_name_val_pair *temp = nvp_head->next;

	*verbosity = 1;
	while (temp) {
		if (strcmp(temp->name, "verbosity") == 0) {
			*verbosity = atoi(temp->value);
			return ;
		}
		temp = temp->next;
	}
	return;
}

int eval_param_tree(struct ecryptfs_ctx *ctx, struct param_node *node,
		    struct ecryptfs_name_val_pair *nvp_head,
		    struct val_node **mnt_params)
{
	void *foo = NULL;
	int rc;

	get_verbosity(nvp_head, &(ctx->verbosity));
	do {
		if (ecryptfs_verbosity) {
			int i;

			syslog(LOG_INFO, "%s: Calling alloc_and_get_val() on "
			       "node = [%p]; node->mnt_opt_names[0] = [%s]\n",
			       __FUNCTION__, node, node->mnt_opt_names[0]);
			for (i = 0; i < node->num_transitions; i++) {
				syslog(LOG_INFO,
				       "%s:  node->tl[%d].val = [%s]\n",
				       __FUNCTION__, i, node->tl[i].val);
			}
		}
		if ((rc = alloc_and_get_val(ctx, node, nvp_head)))
			return rc;
	} while (!(rc = do_transition(ctx, &node, node, nvp_head,
				      mnt_params, &foo)));
	return rc;
}

int ecryptfs_eval_decision_graph(struct ecryptfs_ctx *ctx,
				 struct val_node **mnt_params,
				 struct param_node *root_node,
				 struct ecryptfs_name_val_pair *nvp_head) {
	int rc;

	memset(*mnt_params, 0, sizeof(struct val_node));
	rc = eval_param_tree(ctx, root_node, nvp_head, mnt_params);
	if ((rc > 0) && (rc != MOUNT_ERROR))
		return 0;
	return rc;
}


static void print_whitespace(FILE *file_stream, int depth)
{
	int i;

	for (i = 0; i < depth; i++)
		fprintf(file_stream, " ");
}

void ecryptfs_dump_param_node(FILE *file_stream,
			      struct param_node *param_node, int depth,
			      int recursive);

void ecryptfs_dump_transition_node(FILE *file_stream,
				   struct transition_node *trans_node,
				   int depth, int recursive)
{
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "---------------\n");
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "transition_node\n");
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "---------------\n");
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "val = [%s]\n", trans_node->val);
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "next_token = [%p]\n", trans_node->next_token);
	if (recursive && trans_node->next_token)
		ecryptfs_dump_param_node(file_stream, trans_node->next_token,
					 depth + 1, recursive);
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "---------------\n");
}

void ecryptfs_dump_param_node(FILE *file_stream,
			      struct param_node *param_node, int depth,
			      int recursive)
{
	int i;

	print_whitespace(file_stream, depth);
	fprintf(file_stream, "----------\n");
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "param_node\n");
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "----------\n");
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "mnt_opt_names[0] = [%s]\n",
		param_node->mnt_opt_names[0]);
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "num_transitions = [%d]\n",
		param_node->num_transitions);
	for (i = 0; i < param_node->num_transitions; i++) {
		print_whitespace(file_stream, depth);
		fprintf(file_stream, "transition node [%d]:\n", i);
		ecryptfs_dump_transition_node(file_stream, &param_node->tl[i],
					      depth + 1, recursive);
	}
	print_whitespace(file_stream, depth);
	fprintf(file_stream, "----------\n");

}

void ecryptfs_dump_decision_graph(FILE *file_stream,
				  struct param_node *param_node, int depth)
{
	ecryptfs_dump_param_node(file_stream, param_node, depth, 1);
}

int ecryptfs_insert_params(struct ecryptfs_name_val_pair *nvp,
			   struct param_node *param_node)
{
	int i;
	struct ecryptfs_name_val_pair *cursor = nvp;
	int rc = 0;

	while (cursor->next)
		cursor = cursor->next;
	for (i = 0; i < param_node->num_mnt_opt_names; i++) {
		if ((cursor->next =
		     malloc(sizeof(struct ecryptfs_name_val_pair))) == NULL) {
			syslog(LOG_ERR, "Error attempting to allocate nvp\n");
			rc = -ENOMEM;
			goto out;
		}
		cursor = cursor->next;
		cursor->next = NULL;
		if ((rc = asprintf(&cursor->name, "%s",
				   param_node->mnt_opt_names[i])) == -1) {
			syslog(LOG_ERR, "Error attempting to allocate nvp "
			       "entry for param_node->mnt_opt_names[%d] = "
			       "[%s]\n", i, param_node->mnt_opt_names[i]);
			rc = -ENOMEM;
			goto out;
		}
		rc = 0;
	}
	for (i = 0; i < param_node->num_transitions; i++) {
		if (param_node->tl[i].next_token == NULL)
			continue;
		if ((rc =
		     ecryptfs_insert_params(cursor,
					    param_node->tl[i].next_token))) {
			syslog(LOG_ERR, "Error inserting param; param_node->"
			       "mnt_opt_names[0] = [%s]; transition token "
			       "index = [%d]\n", param_node->mnt_opt_names[0],
			       i);
			goto out;
		}
	}
out:
	return rc;
}

/**
 * ecryptfs_insert_params_in_subgraph
 *
 * For all of the parameter nodes in the subgraph, append a name/value
 * pair to the list with the nvp name set to the parameter node opt
 * name.
 */
int ecryptfs_insert_params_in_subgraph(struct ecryptfs_name_val_pair *nvp,
				       struct transition_node *trans_node)
{
	int rc = 0;

	if (trans_node->next_token)
		rc = ecryptfs_insert_params(nvp, trans_node->next_token);

	return rc;
}

static struct flag_map {
	uint32_t flag_src;
	uint32_t flag_dst;
} nvp_flags_to_param_flags_map[] = {
	{.flag_src = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .flag_dst = ECRYPTFS_PARAM_FLAG_ECHO_INPUT},
};
#define ECRYPTFS_NVP_FLAGS_TO_PARAM_FLAGS_MAP_SIZE 1

static int ecryptfs_map_flags(uint32_t *param_flags, uint32_t nvp_flags)
{
	int i;

	for (i = 0; i < ECRYPTFS_NVP_FLAGS_TO_PARAM_FLAGS_MAP_SIZE; i++)
		if (nvp_flags & nvp_flags_to_param_flags_map[i].flag_src) {
			if (ecryptfs_verbosity)
				syslog(LOG_INFO, "Setting flag [0x%.8x]\n",
				       nvp_flags_to_param_flags_map[i].flag_dst);
			(*param_flags) |=
				nvp_flags_to_param_flags_map[i].flag_dst;
		}
	return 0;
}

struct ecryptfs_subgraph_ctx {
	struct ecryptfs_key_mod *key_mod;
	struct val_node head_val_node;
};

/**
 * ecryptfs_enter_linear_subgraph_tf
 * @ctx:
 * @param_node:
 * @mnt_params:
 * @foo: Pointer memory in the activation record for
 *       eval_param_tree(). Transition node callback functions hang
 *       whatever they want off this pointer. In the case of the
 *       auto-generated linear subgraph, it's a struct containing a
 *       linked list of val_nodes; each param_node->val is duplicated
 *       to each val_node->val. For the last transition function, this
 *       linked list is converted into a parameter array for the key
 *       module. The head val_node is always empty and serves only as
 *       a placeholder.
 *
 * This is the entrance transition function callback. This means that
 * it is a transition node to the key module selection parameter
 * node. This means that the parameter node's value indicates the
 * alias of the key module to which this function applies. That is why
 * we call ecryptfs_find_key_mod() to get the key module. The exit
 * transition function is going to need this key module struct so that
 * it can attach the final parameter value array to it.
 */
static int
ecryptfs_enter_linear_subgraph_tf(struct ecryptfs_ctx *ctx,
				  struct param_node *param_node,
				  struct val_node **mnt_params, void **foo)
{
	struct ecryptfs_subgraph_ctx *subgraph_ctx;
	int rc = 0;

	if ((subgraph_ctx = malloc(sizeof(struct ecryptfs_subgraph_ctx)))
	    == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	memset(subgraph_ctx, 0, sizeof(struct ecryptfs_subgraph_ctx));
	if ((rc = ecryptfs_find_key_mod(&subgraph_ctx->key_mod, ctx,
					param_node->val))) {
		syslog(LOG_ERR, "%s: Cannot find key_mod for param_node with "
		       "val = [%s]\n", __FUNCTION__, param_node->val);
		goto out;
	}
	(*foo) = (void *)subgraph_ctx;
out:
	return rc;
}

/**
 * @foo: Contains a struct with a linked list of val_node
 *       structs. Parameter lists are going to be very short, so
 *       there's no list handling optimization here; we just keep
 *       everything in order.
 */
static int
ecryptfs_linear_subgraph_val_tf(struct ecryptfs_ctx *ctx,
				  struct param_node *param_node,
				  struct val_node **mnt_params, void **foo)
{
	struct val_node *val_node;
	struct val_node *walker;
	struct ecryptfs_subgraph_ctx *subgraph_ctx;
	int rc = 0;

	if (param_node->val == NULL) {
		syslog(LOG_WARNING, "No value supplied for parameter node with "
		       "primary opt name [%s]\n", param_node->mnt_opt_names[0]);
		goto out;
	}
	if ((val_node = malloc(sizeof(struct val_node))) == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	memset(val_node, 0, sizeof(struct val_node));
	if ((rc = asprintf((char **)&val_node->val, "%s", param_node->val))
	    == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = 0;
	subgraph_ctx = (struct ecryptfs_subgraph_ctx *)(*foo);
	walker = &subgraph_ctx->head_val_node;
	while (walker->next)
		walker = walker->next;
	walker->next = val_node;
out:
	return rc;
}

/**
 * ecryptfs_exit_linear_subgraph_tf
 * @foo: Linked list of val_node structs.
 *
 * This is executed when transitioning from the param_node immediately
 * after the last param_node that deals with a value. The first
 * element in the list is an empty placeholder and shall always
 * exist. This function converts the parameter value linked list into
 * a parameter value array for the module to use.
 */
static int
ecryptfs_exit_linear_subgraph_tf(struct ecryptfs_ctx *ctx,
				 struct param_node *param_node,
				 struct val_node **mnt_params, void **foo)
{
	struct val_node *curr;
	uint32_t num_param_vals = 0;
	struct key_mod_param_val *param_vals;
	struct ecryptfs_subgraph_ctx *subgraph_ctx;
	char *sig_mnt_opt;
	char sig[ECRYPTFS_SIG_SIZE_HEX + 1];
	int i = 0;
	int rc = 0;

	subgraph_ctx = (struct ecryptfs_subgraph_ctx *)(*foo);
	curr = subgraph_ctx->head_val_node.next;
	while (curr) {
		num_param_vals++;
		curr = curr->next;
	}
	subgraph_ctx->key_mod->num_param_vals = num_param_vals;
	if (num_param_vals == 0) {
		subgraph_ctx->key_mod->param_vals = NULL;
		goto out_free_subgraph_ctx;
	}
	param_vals = malloc(sizeof(struct key_mod_param_val) * num_param_vals);
	if (param_vals == NULL) {
		rc = -ENOMEM;
		goto out_free_list_and_subgraph_ctx;
	}
	curr = subgraph_ctx->head_val_node.next;
	while (curr) {
		if (curr->val) {
			if ((rc = asprintf(&param_vals[i].val, "%s",
					   (char *)curr->val)) == -1) {
				rc = -ENOMEM;
				goto out_free_list_and_subgraph_ctx;
			}
		} else
			param_vals[i].val = NULL;
		i++;
		curr = curr->next;
	}
	subgraph_ctx->key_mod->param_vals = param_vals;
	if ((rc = ecryptfs_add_key_module_key_to_keyring(
		     sig, subgraph_ctx->key_mod)) < 0) {
		syslog(LOG_ERR, "Error attempting to add key to keyring for "
		       "key module [%s]; rc = [%d]\n",
		       subgraph_ctx->key_mod->alias, rc);
		goto out_free_list_and_subgraph_ctx;
	}
	if ((rc = asprintf(&sig_mnt_opt, "ecryptfs_sig=%s", sig)) == -1) {
		rc = -ENOMEM;
		goto out_free_list_and_subgraph_ctx;
	}
	rc = stack_push(mnt_params, sig_mnt_opt);
out_free_list_and_subgraph_ctx:
	curr = subgraph_ctx->head_val_node.next;
	while (curr) {
		struct val_node *next;

		next = curr->next;
		if (curr->val)
			free(curr->val);
		free(curr);
		curr = next;
	}
out_free_subgraph_ctx:
	free(subgraph_ctx);

	return rc;
}

/**
 * ecryptfs_build_linear_subgraph
 * @trans_node: This function allocates this new transition node into
 *              its generated subgraph
 * @key_mod: The key module containing the parameter list to use as
 *           the basis for generating the subgraph
 *
 * Generates a subgraph of the decision tree from the set of
 * parameters provided by the key module.
 *
 * Callbacks manage the conversion of the parameter node subgraph to
 * the parameter value array that the module makes use of. The first
 * callback initializes the val_node data structure to be an empty
 * linked list of values. The subsequent callbacks append the
 * parameter node values to the list. The last callback allocates a
 * chunk of memory for the parameter values array
 * (key_mod->param_vals), transfers the values in the list into that
 * array, and frees the list. It then calls
 * ecryptfs_add_key_module_key_to_keyring() with this parameter value
 * list. This, in turn, calls ecryptfs_generate_key_payload(), which
 * calls the module's get_blob() function and takes steps to generate
 * the key signature. The exit callback appends an ecryptfs_sig=
 * parameter to the mnt_params list.
 *
 * A dummy param_node is built by setting the NO_VALUE flag in
 * param_node->flags; the transition_node that will be taken by
 * default needs to have its value set to the string "default".
 *
 * The total number of param_node structs generated is the number of
 * parameters plus two. The last two nodes are for (1) providing a
 * callback to convert the nvp list to a params array and (2)
 * providing a dummy node that can have its own transition set by
 * libecryptfs to whatever it wants to set it to.
 */
int ecryptfs_build_linear_subgraph(struct transition_node **trans_node,
				   struct ecryptfs_key_mod *key_mod)
{
	struct param_node *param_node;
	struct transition_node *tmp_tn;
	struct key_mod_param *params;
	uint32_t num_params;
	uint32_t i;
	int rc = 0;

	if ((rc = key_mod->ops->get_params(&params, &num_params))) {
		syslog(LOG_WARNING, "Key module [%s] returned error whilst "
		       "retrieving parameter list; rc = [%d]\n",
		       key_mod->alias, rc);
		goto out;
	}
	if ((params == NULL) || (num_params == 0)) {
		syslog(LOG_WARNING, "Key module [%s] has empty "
		       "parameter list\n", key_mod->alias);
		rc = -EINVAL;
	}
	if (((*trans_node) = tmp_tn = malloc(sizeof(struct transition_node)))
	    == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	memset(tmp_tn, 0, sizeof(struct transition_node));
	if ((rc = asprintf(&tmp_tn->val, "%s", key_mod->alias)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = asprintf(&tmp_tn->pretty_val, "%s", key_mod->alias))
	    == -1) {
		rc = -ENOMEM;
		goto out;
	}
	tmp_tn->trans_func = &ecryptfs_enter_linear_subgraph_tf;
	rc = 0;
	param_node = NULL;
	for (i = 0; i < num_params; i++) {
		if ((param_node = malloc(sizeof(struct param_node))) == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		memset(param_node, 0, sizeof(struct param_node));
		if ((rc = asprintf(&param_node->mnt_opt_names[0], "%s",
				   params[i].option)) == -1) {
			rc = -ENOMEM;
			goto out;
		}
		param_node->num_mnt_opt_names = 1;
		if (params[i].description) {
			if ((rc = asprintf(&param_node->prompt, "%s",
					   params[i].description)) == -1) {
				rc = -ENOMEM;
				goto out;
			}
		} else
			if ((rc = asprintf(&param_node->prompt, "%s",
					   params[i].option)) == -1) {
				rc = -ENOMEM;
				goto out;
			}
		if (params[i].default_val)
			if ((rc = asprintf(&param_node->default_val, "%s",
					   params[i].default_val)) == -1) {
				rc = -ENOMEM;
				goto out;
			}
		if (params[i].suggested_val)
			if ((rc = asprintf(&param_node->suggested_val, "%s",
					   params[i].suggested_val)) == -1) {
				rc = -ENOMEM;
				goto out;
			}
		rc = 0;
		param_node->val_type = VAL_STR;
		ecryptfs_map_flags(&param_node->flags, params[i].flags);
		tmp_tn->next_token = param_node;
		tmp_tn = &param_node->tl[0];
		if ((rc = asprintf(&tmp_tn->val, "default")) == -1) {
			rc = -ENOMEM;
			goto out;
		}
		tmp_tn->trans_func = &ecryptfs_linear_subgraph_val_tf;
		param_node->num_transitions = 1;
	}
	if ((param_node = malloc(sizeof(struct param_node))) == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	memset(param_node, 0, sizeof(struct param_node));
	if ((rc = asprintf(&param_node->mnt_opt_names[0],
			   "linear_subgraph_exit_dummy_node")) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	param_node->num_mnt_opt_names = 1;
	param_node->flags |= ECRYPTFS_PARAM_FLAG_NO_VALUE;
	tmp_tn->next_token = param_node;
	tmp_tn = &param_node->tl[0];
	if ((rc = asprintf(&tmp_tn->val, "default")) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = 0;
	param_node->num_transitions = 1;
	tmp_tn->trans_func = &ecryptfs_exit_linear_subgraph_tf;
out:
	return rc;
}
