/**
 * Copyright (C) 2006 International Business Machines
 * Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
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
#include "../include/ecryptfs.h"
#include "../include/decision_graph.h"

struct param_node plaintext_arr[] = {
	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"passthrough"},
	 .prompt = "Enable Plaintext Passthrough",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "0",
	 .flags = 0,
	 .num_transitions = 2,
	 .tl = {{.val = "1",
		 .pretty_val = "Yes",
		 .next_token = NULL,
		 .trans_func = NULL},
	 	{.val = "0",
		 .pretty_val = "No",
		 .next_token = NULL,
		 .trans_func = NULL}}}
};
