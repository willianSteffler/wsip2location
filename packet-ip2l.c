/* packet-ip2l.c
 * Routines for ip2location dissection
 * Copyright 2020, IP to Location <wstefflerdev@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#include <config.h>
#include <stdio.h>

#if 0
/* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
...
#endif

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/prefs.h>    /* Include only as needed */

#if 0
/* IF AND ONLY IF your protocol dissector exposes code to other dissectors
 * (which most dissectors don't need to do) then the 'public' prototypes and
 * data structures can go in the header file packet-ip2l.h. If not, then
 * a header file is not needed at all and this #include statement can be
 * removed. */
#include "packet-ip2l.h"
#endif

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_ip2l(void);
void proto_register_ip2l(void);

/* Initialize the protocol and registered fields */
static int proto_ip2l = -1;

static int hf_ip2l_src_addrs = -1;
static int hf_ip2l_dest_addrs = -1;

static int hf_ip2l_src_city = -1;
static int hf_ip2l_src_country = -1;
static int hf_ip2l_src_lat = -1;
static int hf_ip2l_src_lon = -1;
static int hf_ip2l_src_tz = -1;
static int hf_ip2l_src_zc = -1;

static int hf_ip2l_dest_city = -1;
static int hf_ip2l_dest_country = -1;
static int hf_ip2l_dest_lat = -1;
static int hf_ip2l_dest_lon = -1;
static int hf_ip2l_dest_tz = -1;
static int hf_ip2l_dest_zc = -1;

/* Global sample preference ("controls" display of numbers) */
static gboolean pref_hex = FALSE;
/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
#define ip2l_IP_VERSION 4
static guint ipv_pref = ip2l_IP_VERSION;

/* Initialize the subtree pointers */
static gint ett_ip2l_src = -1;
static gint ett_ip2l_src_city = -1;
static gint ett_ip2l_src_country = -1;
static gint ett_ip2l_src_lat = -1;
static gint ett_ip2l_src_lon = -1;
static gint ett_ip2l_src_tz = -1;
static gint ett_ip2l_src_zc = -1;

static gint ett_ip2l_dest = -1;
static gint ett_ip2l_dest_city = -1;
static gint ett_ip2l_dest_country = -1;
static gint ett_ip2l_dest_lat = -1;
static gint ett_ip2l_dest_lon = -1;
static gint ett_ip2l_dest_tz = -1;
static gint ett_ip2l_dest_zc = -1;


static char* addrs_tostring( guint32 ipAddress ) {
    guint8 octet[4];
    char ipAddressFinal[16];
    for(int i = 0 ; i < 4 ; i++)
    {
        octet[i] = ipAddress >> (i * 8);
    }
    sprintf(ipAddressFinal, "%d.%d.%d.%d", octet[3], octet[2], octet[1], octet[0]);

    return ipAddressFinal;
}


/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define ip2l_MIN_LENGTH 20

/* Code to actually dissect the packets */
static int
dissect_ip2l(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_item *ti_dst;
    proto_item *ti_src;
    proto_tree * ip2l_src_tree;
    proto_tree * ip2l_dest_tree;

    /* Other misc. local variables. */
    guint8      version = 0;
    guint       offset = 0;
    guint32 addrs_src,addrs_dest;

    /*** HEURISTICS ***/

    /* First, if at all possible, do some heuristics to check if the packet
     * cannot possibly belong to your protocol.  This is especially important
     * for protocols directly on top of TCP or UDP where port collisions are
     * common place (e.g., even though your protocol uses a well known port,
     * someone else may set up, for example, a web server on that port which,
     * if someone analyzed that web server's traffic in Wireshark, would result
     * in Wireshark handing an HTTP packet to your dissector).
     *
     * For example:
     */

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < ip2l_MIN_LENGTH)
        return 0;

    /* Check that there's enough data present to run the heuristics. If there
     * isn't, reject the packet; it will probably be dissected as data and if
     * the user wants it dissected despite it being short they can use the
     * "Decode-As" functionality. If your heuristic needs to look very deep into
     * the packet you may not want to require *all* data to be present, but you
     * should ensure that the heuristic does not access beyond the captured
     * length of the packet regardless. */
    if (tvb_captured_length(tvb) < 1)
        return 0;

    /* Fetch some values from the packet header using tvb_get_*(). If these
     * values are not valid/possible in your protocol then return 0 to give
     * some other dissector a chance to dissect it. */
    version = tvb_get_bits8(tvb, 0, 4);
    if(version != 4)
        return 0;
    
    addrs_src = tvb_get_ipv4(tvb,offset + 12);
    addrs_dest = tvb_get_ipv4(tvb,offset + 16);

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'ip2l',
     * and the 'Info' column which can be much wider and contain misc. summary
     * information (for example, the port number for TCP packets).
     *
     * If you are setting the column to a constant string, use "col_set_str()",
     * as it's more efficient than the other "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
     * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
     * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
     * more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of ip2l */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ip2l");

#if 0
    /* If you will be fetching any data from the packet before filling in
     * the Info column, clear that column first in case the calls to fetch
     * data from the packet throw an exception so that the Info column doesn't
     * contain data left over from the previous dissector: */
    col_clear(pinfo->cinfo, COL_INFO);
#endif

    col_set_str(pinfo->cinfo, COL_INFO, "XXX Request");

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_ip2l, tvb, 0, -1, ENC_NA);
    ti_src = proto_tree_add_ipv4(ti,hf_ip2l_src_addrs,tvb,offset + 12, 4, addrs_src);
    ti_dst = proto_tree_add_ipv4(ti,hf_ip2l_dest_addrs,tvb,offset + 16, 4, addrs_dest);


    ip2l_src_tree = proto_item_add_subtree(ti_src, ett_ip2l_src);
    ip2l_dest_tree = proto_item_add_subtree(ti_dst, ett_ip2l_dest);

    /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */

    proto_tree_add_string(ip2l_src_tree,hf_ip2l_src_city,tvb,0,-1,"src cidade");
    proto_tree_add_string(ip2l_src_tree,hf_ip2l_src_country,tvb,0,-1,"src país");
    proto_tree_add_double(ip2l_src_tree,hf_ip2l_src_lat,tvb,0,-1,1.1);
    proto_tree_add_double(ip2l_src_tree,hf_ip2l_src_lon,tvb,0,-1,1.2);
    proto_tree_add_string(ip2l_src_tree,hf_ip2l_src_tz,tvb,0,-1,"src tz");
    proto_tree_add_string(ip2l_src_tree,hf_ip2l_src_zc,tvb,0,-1,"src zc");

    proto_tree_add_string(ip2l_dest_tree,hf_ip2l_dest_city,tvb,0,-1,"dest cidade");
    proto_tree_add_string(ip2l_dest_tree,hf_ip2l_dest_country,tvb,0,-1,"dest país");
    proto_tree_add_double(ip2l_dest_tree,hf_ip2l_dest_lat,tvb,0,-1,1.1);
    proto_tree_add_double(ip2l_dest_tree,hf_ip2l_dest_lon,tvb,0,-1,1.2);
    proto_tree_add_string(ip2l_dest_tree,hf_ip2l_dest_tz,tvb,0,-1,"dest tz");
    proto_tree_add_string(ip2l_dest_tree,hf_ip2l_dest_zc,tvb,0,-1,"dest zc");

    /* Continue adding tree items to process the packet here... */

    /* If this protocol has a sub-dissector call it here, see section 1.8 of
     * README.dissector for more information. */

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_ip2l(void)
{
    module_t        *ip2l_module;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_ip2l_src_addrs,
          { "SRC IP Address", "ip2l.src_addrs",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_src_city,
          { "SRC IP City", "ip2l.src_city",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_src_country,
          { "SRC IP Country", "ip2l.src_country",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_src_lat,
          { "SRC IP Latitude", "ip2l.src_lat",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_src_lon,
          { "SRC IP Longitude", "ip2l.src_lon",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_src_tz,
          { "SRC IP Time-zone", "ip2l.src_tz",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_src_zc,
          { "SRC IP Zip Code", "ip2l.src_zc",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },{ &hf_ip2l_dest_addrs,
          { "DEST IP Address", "ip2l.dest_addrs",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_dest_city,
          { "DEST IP City", "ip2l.dest_city",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_dest_country,
          { "DEST IP Country", "ip2l.dest_country",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_dest_lat,
          { "DEST IP Latitude", "ip2l.dest_lat",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_dest_lon,
          { "DEST IP Longitude", "ip2l.dest_lon",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_dest_tz,
          { "DEST IP Time-zone", "ip2l.dest_tz",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        },
        { &hf_ip2l_dest_zc,
          { "SRC IP Zip Code", "ip2l.source_zc",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "NULL", HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ip2l_src,
        &ett_ip2l_dest
    };

    /* Setup protocol subtree array */
    static gint *ett_src[] = {    
        &ett_ip2l_src_city,
        &ett_ip2l_src_country,
        &ett_ip2l_src_lat,
        &ett_ip2l_src_lon,
        &ett_ip2l_src_tz,
        &ett_ip2l_src_zc
    };

    /* Setup protocol subtree array */
    static gint *ett_dest[] = {
        &ett_ip2l_dest_city,
        &ett_ip2l_dest_country,
        &ett_ip2l_dest_lat,
        &ett_ip2l_dest_lon,
        &ett_ip2l_dest_tz,
        &ett_ip2l_dest_zc
    };

    /* Register the protocol name and description */
    proto_ip2l = proto_register_protocol("ip2location",
            "ip2l", "ip2l");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_ip2l, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    proto_register_subtree_array(ett_src,array_length(ett_src));
    proto_register_subtree_array(ett_dest,array_length(ett_dest));

    /* Register a preferences module (see section 2.6 of README.dissector
     * for more details). Registration of a prefs callback is not required
     * if there are no preferences that affect protocol registration (an example
     * of a preference that would affect registration is a port preference).
     * If the prefs callback is not needed, use NULL instead of
     * proto_reg_handoff_ip2l in the following.
     */
    ip2l_module = prefs_register_protocol(proto_ip2l,
            proto_reg_handoff_ip2l);

    /* Register a preferences module under the preferences subtree.
     * Only use this function instead of prefs_register_protocol (above) if you
     * want to group preferences of several protocols under one preferences
     * subtree.
     *
     * Argument subtree identifies grouping tree node name, several subnodes can
     * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
     * will be accessible under Protocols->OSI->X.500-><ip2l>
     * preferences node.
     */
    ip2l_module = prefs_register_protocol_subtree("",
            proto_ip2l, proto_reg_handoff_ip2l);

    /* Register a simple example preference */
    prefs_register_bool_preference(ip2l_module, "show_hex",
            "Display numbers in Hex",
            "Enable to display numerical values in hexadecimal.",
            &pref_hex);

    /* Register an example port preference */
    prefs_register_uint_preference(ip2l_module, "ip.version", "ip2l IP Version",
            " ip2l IP version if other than the default",
            10, &ipv_pref);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_ip2l(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t ip2l_handle;
    static int current_ipv;

    if (!initialized) {
        /* Use create_dissector_handle() to indicate that
         * dissect_ip2l() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to ip2location).
         */
        ip2l_handle = create_dissector_handle(dissect_ip2l,
                proto_ip2l);
        initialized = TRUE;

    } else {
        /* If you perform registration functions which are dependent upon
         * prefs then you should de-register everything which was associated
         * with the previous settings and re-register using the new prefs
         * settings here. In general this means you need to keep track of
         * the ip2l_handle and the value the preference had at the time
         * you registered.  The ip2l_handle value and the value of the
         * preference can be saved using local statics in this
         * function (proto_reg_handoff).
         */
        dissector_delete_uint("ip.version", current_ipv, ip2l_handle);
    }

    current_ipv = ipv_pref;

    dissector_add_uint("ip.version", current_ipv, ip2l_handle);
}

#if 0

/* Simpler form of proto_reg_handoff_ip2l which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_ip2l(void)
{
    dissector_handle_t ip2l_handle;

    /* Use create_dissector_handle() to indicate that dissect_ip2l()
     * returns the number of bytes it dissected (or 0 if it thinks the packet
     * does not belong to ip2location).
     */
    ip2l_handle = create_dissector_handle(dissect_ip2l,
            proto_ip2l);
    
    dissector_add_uint_with_preference("tcp.port", ip2l_IP_VERSION, ip2l_handle);
}
#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
