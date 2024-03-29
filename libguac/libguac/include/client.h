
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is libguac.
 *
 * The Initial Developer of the Original Code is
 * Michael Jumper.
 * Portions created by the Initial Developer are Copyright (C) 2010
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */


#ifndef _GUAC_CLIENT_H
#define _GUAC_CLIENT_H

#include <stdarg.h>

#include "socket.h"
#include "protocol.h"

/**
 * Provides functions and structures required for defining (and handling) a proxy client.
 *
 * @file client.h
 */

/**
 * String prefix which begins the library filename of all client plugins.
 */
#define GUAC_PROTOCOL_LIBRARY_PREFIX "libguac-client-"

/**
 * String suffix which ends the library filename of all client plugins.
 */
#define GUAC_PROTOCOL_LIBRARY_SUFFIX ".so"

/**
 * The maximum number of characters (COUNTING NULL TERMINATOR) to allow
 * for protocol names within the library filename of client plugins.
 */
#define GUAC_PROTOCOL_NAME_LIMIT 256

/**
 * The maximum number of characters (INCLUDING NULL TERMINATOR) that a
 * character array containing the concatenation of the library prefix,
 * protocol name, and suffix can contain, assuming the protocol name is
 * limited to GUAC_PROTOCOL_NAME_LIMIT characters.
 */
#define GUAC_PROTOCOL_LIBRARY_LIMIT (                                  \
                                                                       \
      sizeof(GUAC_PROTOCOL_LIBRARY_PREFIX) - 1 /* "libguac-client-" */ \
    +        GUAC_PROTOCOL_NAME_LIMIT      - 1 /* [up to 256 chars] */ \
    + sizeof(GUAC_PROTOCOL_LIBRARY_SUFFIX) - 1 /* ".so"             */ \
    + 1                                        /* NULL terminator   */ \
                                                                       \
)


typedef struct guac_client guac_client;
typedef struct guac_client_plugin guac_client_plugin;

/**
 * Handler for server messages (where "server" refers to the server that
 * the proxy client is connected to).
 */
typedef int guac_client_handle_messages(guac_client* client);

/**
 * Handler for Guacamole mouse events.
 */
typedef int guac_client_mouse_handler(guac_client* client, int x, int y, int button_mask);

/**
 * Handler for Guacamole key events.
 */
typedef int guac_client_key_handler(guac_client* client, int keysym, int pressed);

/**
 * Handler for Guacamole clipboard events.
 */
typedef int guac_client_clipboard_handler(guac_client* client, char* copied);

/**
 * Handler for freeing up any extra data allocated by the client
 * implementation.
 */
typedef int guac_client_free_handler(guac_client* client);

/**
 * Handler for logging messages
 */
typedef void guac_client_log_handler(guac_client* client, const char* format, va_list args); 

/**
 * Handler which should initialize the given guac_client.
 */
typedef int guac_client_init_handler(guac_client* client, int argc, char** argv);

/**
 * The flag set in the mouse button mask when the left mouse button is down.
 */
#define GUAC_CLIENT_MOUSE_LEFT        0x01

/**
 * The flag set in the mouse button mask when the middle mouse button is down.
 */
#define GUAC_CLIENT_MOUSE_MIDDLE      0x02

/**
 * The flag set in the mouse button mask when the right mouse button is down.
 */
#define GUAC_CLIENT_MOUSE_RIGHT       0x04

/**
 * The flag set in the mouse button mask when the mouse scrollwheel is scrolled
 * up. Note that mouse scrollwheels are actually sets of two buttons. One
 * button is pressed and released for an upward scroll, and the other is
 * pressed and released for a downward scroll. Some mice may actually implement
 * these as separate buttons, not a wheel.
 */
#define GUAC_CLIENT_MOUSE_SCROLL_UP   0x08

/**
 * The flag set in the mouse button mask when the mouse scrollwheel is scrolled
 * down. Note that mouse scrollwheels are actually sets of two buttons. One
 * button is pressed and released for an upward scroll, and the other is
 * pressed and released for a downward scroll. Some mice may actually implement
 * these as separate buttons, not a wheel.
 */
#define GUAC_CLIENT_MOUSE_SCROLL_DOWN 0x10

/**
 * The minimum number of buffers to create before allowing free'd buffers to
 * be reclaimed. In the case a protocol rapidly creates, uses, and destroys
 * buffers, this can prevent unnecessary reuse of the same buffer (which
 * would make draw operations unnecessarily synchronous).
 */
#define GUAC_BUFFER_POOL_INITIAL_SIZE 1024

/**
 * Possible current states of the Guacamole client. Currently, the only
 * two states are GUAC_CLIENT_RUNNING and GUAC_CLIENT_STOPPING.
 */
typedef enum guac_client_state {

    /**
     * The state of the client from when it has been allocated by the main
     * daemon until it is killed or disconnected.
     */
    GUAC_CLIENT_RUNNING,

    /**
     * The state of the client when a stop has been requested, signalling the
     * I/O threads to shutdown.
     */
    GUAC_CLIENT_STOPPING

} guac_client_state;

/**
 * A handle to a client plugin, containing enough information about the
 * plugin to complete the initial protocol handshake and instantiate a new
 * client supporting the protocol provided by the client plugin. 
 */
struct guac_client_plugin {

    /**
     * Reference to dlopen'd client plugin.
     */
    void* __client_plugin_handle;

    /**
     * Reference to the init handler of this client plugin. This
     * function will be called when the client plugin is started.
     */
    guac_client_init_handler* init_handler;

    /**
     * NULL-terminated array of all arguments accepted by this client
     * plugin, in order. The values of these arguments will be passed
     * to the init_handler if the client plugin is started.
     */
    const char** args;

};

/**
 * Guacamole proxy client.
 *
 * Represents a Guacamole proxy client (the client which communicates to
 * a server on behalf of Guacamole, on behalf of the web-client).
 */
struct guac_client {

    /**
     * The guac_socket structure to be used to communicate with the web-client.
     * It is expected that the implementor of any Guacamole proxy client will
     * provide their own mechanism of I/O for their protocol. The guac_socket
     * structure is used only to communicate conveniently with the Guacamole
     * web-client.
     */
    guac_socket* socket;

    /**
     * The current state of the client. When the client is first allocated,
     * this will be initialized to GUAC_CLIENT_RUNNING. It will remain at
     * GUAC_CLIENT_RUNNING until an event occurs which requires the client to
     * shutdown, at which point the state becomes GUAC_CLIENT_STOPPING.
     */
    guac_client_state state;

    /**
     * The time (in milliseconds) of receipt of the last sync message from
     * the client.
     */
    guac_timestamp last_received_timestamp;

    /**
     * The time (in milliseconds) that the last sync message was sent to the
     * client.
     */
    guac_timestamp last_sent_timestamp;

    /**
     * Arbitrary reference to proxy client-specific data. Implementors of a
     * Guacamole proxy client can store any data they want here, which can then
     * be retrieved as necessary in the message handlers.
     */
    void* data;

    /**
     * Handler for server messages. If set, this function will be called
     * occasionally by the Guacamole proxy to give the client a chance to
     * handle messages from whichever server it is connected to.
     *
     * Example:
     * @code
     *     int handle_messages(guac_client* client);
     *
     *     int guac_client_init(guac_client* client, int argc, char** argv) {
     *         client->handle_messages = handle_messages;
     *     }
     * @endcode
     */
    guac_client_handle_messages* handle_messages;

    /**
     * Handler for mouse events sent by the Gaucamole web-client.
     *
     * The handler takes the integer mouse X and Y coordinates, as well as
     * a button mask containing the bitwise OR of all button values currently
     * being pressed. Those values are:
     *
     * <table>
     *     <tr><th>Button</th>          <th>Value</th></tr>
     *     <tr><td>Left</td>            <td>1</td></tr>
     *     <tr><td>Middle</td>          <td>2</td></tr>
     *     <tr><td>Right</td>           <td>4</td></tr>
     *     <tr><td>Scrollwheel Up</td>  <td>8</td></tr>
     *     <tr><td>Scrollwheel Down</td><td>16</td></tr>
     * </table>

     * Example:
     * @code
     *     int mouse_handler(guac_client* client, int x, int y, int button_mask);
     *
     *     int guac_client_init(guac_client* client, int argc, char** argv) {
     *         client->mouse_handler = mouse_handler;
     *     }
     * @endcode
     */
    guac_client_mouse_handler* mouse_handler;

    /**
     * Handler for key events sent by the Guacamole web-client.
     *
     * The handler takes the integer X11 keysym associated with the key
     * being pressed/released, and an integer representing whether the key
     * is being pressed (1) or released (0).
     *
     * Example:
     * @code
     *     int key_handler(guac_client* client, int keysym, int pressed);
     *
     *     int guac_client_init(guac_client* client, int argc, char** argv) {
     *         client->key_handler = key_handler;
     *     }
     * @endcode
     */
    guac_client_key_handler* key_handler;

    /**
     * Handler for clipboard events sent by the Guacamole web-client. This
     * handler will be called whenever the web-client sets the data of the
     * clipboard.
     *
     * This handler takes a single string which contains the text which
     * has been set in the clipboard. This text is already unescaped from
     * the Guacamole escaped version sent within the clipboard message
     * in the protocol.
     *
     * Example:
     * @code
     *     int clipboard_handler(guac_client* client, char* copied);
     *
     *     int guac_client_init(guac_client* client, int argc, char** argv) {
     *         client->clipboard_handler = clipboard_handler;
     *     }
     * @endcode
     */
    guac_client_clipboard_handler* clipboard_handler;

    /**
     * Handler for freeing data when the client is being unloaded.
     *
     * This handler will be called when the client needs to be unloaded
     * by the proxy, and any data allocated by the proxy client should be
     * freed.
     *
     * Note that this handler will NOT be called if the client's
     * guac_client_init() function fails.
     *
     * Implement this handler if you store data inside the client.
     *
     * Example:
     * @code
     *     int free_handler(guac_client* client);
     *
     *     int guac_client_init(guac_client* client, int argc, char** argv) {
     *         client->free_handler = free_handler;
     *     }
     * @endcode
     */
    guac_client_free_handler* free_handler;

    /**
     * Handler for logging informational messages. This handler will be called
     * via guac_client_log_info() when the client needs to log information.
     *
     * In general, only programs loading the client should implement this
     * handler, as those are the programs that would provide the logging
     * facilities.
     *
     * Client implementations should expect these handlers to already be
     * set.
     *
     * Example:
     * @code
     *     void log_handler(guac_client* client, const char* format, va_list args);
     *
     *     void function_of_daemon() {
     *
     *         guac_client* client = [pass log_handler to guac_client_plugin_get_client()];
     *
     *     }
     * @endcode
     */
    guac_client_log_handler* log_info_handler;


    /**
     * Handler for logging error messages. This handler will be called
     * via guac_client_log_error() when the client needs to log an error.
     *
     * In general, only programs loading the client should implement this
     * handler, as those are the programs that would provide the logging
     * facilities.
     *
     * Client implementations should expect these handlers to already be
     * set.
     *
     * Example:
     * @code
     *     void log_handler(guac_client* client, const char* format, va_list args);
     *
     *     void function_of_daemon() {
     *
     *         guac_client* client = [pass log_handler to guac_client_plugin_get_client()];
     *
     *     }
     * @endcode
     */
    guac_client_log_handler* log_error_handler;

    /**
     * The index of the next available buffer.
     */
    int __next_buffer_index;

    /**
     * The head pointer of the list of all available (allocated but not used)
     * buffers.
     */
    guac_layer* __available_buffers;

    /**
     * Pointer to the last buffer in the list of all available buffers.
     */
    guac_layer* __last_available_buffer;

    /**
     * The index of the next available layer.
     */
    int __next_layer_index;

    /**
     * The head pointer of the list of all available (allocated but not used)
     * layers.
     */
    guac_layer* __available_layers;

    /**
     * Pointer to the last layer in the list of all available layers.
     */
    guac_layer* __last_available_layer;

    /**
     * The head pointer of the list of all allocated layers, regardless of use
     * status.
     */
    guac_layer* __all_layers;

};

/**
 * Open the plugin which provides support for the given protocol, if it
 * exists.
 *
 * @param protocol The name of the protocol to retrieve the client plugin
 *                 for.
 * @return The client plugin supporting the given protocol, or NULL if
 *         an error occurs or no such plugin exists.
 */
guac_client_plugin* guac_client_plugin_open(const char* protocol);

/**
 * Close the given plugin, releasing all associated resources. This function
 * must be called after use of a client plugin is finished.
 *
 * @param plugin The client plugin to close.
 * @return Zero on success, non-zero if an error occurred while releasing
 *         the resources associated with the plugin.
 */
int guac_client_plugin_close(guac_client_plugin* plugin);

/**
 * Initialize and return a new guac_client. The pluggable client will be
 * initialized using the arguments provided.
 *
 * @param plugin The client plugin to use to create the new client.
 * @param socket The guac_socket the client should use for communication.
 * @param argc The number of arguments being passed to the client.
 * @param argv All arguments to be passed to the client.
 * @param log_info_handler Info logging handler to provide to the client before
 *                         initializing.
 * @param log_error_handler Error logging handler to provide to the client
 *                          before initializing.
 * @return A pointer to the newly initialized client.
 */
guac_client* guac_client_plugin_get_client(guac_client_plugin* plugin,
        guac_socket* socket, int argc, char** argv,
        guac_client_log_handler* log_info_handler,
        guac_client_log_handler* log_error_handler);

/**
 * Free all resources associated with the given client.
 *
 * @param client The proxy client to free all reasources of.
 */
void guac_client_free(guac_client* client);

/**
 * Call the appropriate handler defined by the given client for the given
 * instruction. A comparison is made between the instruction opcode and the
 * initial handler lookup table defined in client-handlers.c. The intial
 * handlers will in turn call the client's handler (if defined).
 *
 * @param client The proxy client whose handlers should be called.
 * @param instruction The instruction to pass to the proxy client via the
 *                    appropriate handler.
 */
int guac_client_handle_instruction(guac_client* client, guac_instruction* instruction);

/**
 * Allocates a new buffer (invisible layer). An arbitrary index is
 * automatically assigned if no existing buffer is available for use.
 *
 * @param client The proxy client to allocate the buffer for.
 * @return The next available buffer, or a newly allocated buffer.
 */
guac_layer* guac_client_alloc_buffer(guac_client* client);

/**
 * Allocates a new layer. An arbitrary index is automatically assigned
 * if no existing layer is available for use.
 *
 * @param client The proxy client to allocate the layer buffer for.
 * @return The next available layer, or a newly allocated layer.
 */
guac_layer* guac_client_alloc_layer(guac_client* client);

/**
 * Returns the given buffer to the pool of available buffers, such that it
 * can be reused by any subsequent call to guac_client_allow_buffer().
 *
 * @param client The proxy client to return the buffer to.
 * @param layer The buffer to return to the pool of available buffers.
 */
void guac_client_free_buffer(guac_client* client, guac_layer* layer);

/**
 * Returns the given layer to the pool of available layers, such that it
 * can be reused by any subsequent call to guac_client_allow_layer().
 *
 * @param client The proxy client to return the layer to.
 * @param layer The buffer to return to the pool of available layer.
 */
void guac_client_free_layer(guac_client* client, guac_layer* layer);


/**
 * Logs an informational message in the log used by the given client. The
 * logger used will normally be defined by guacd (or whichever program loads
 * the proxy client) by setting the logging handlers of the client when it is
 * loaded.
 *
 * @param client The proxy client to log an informational message for.
 * @param format A printf-style format string to log.
 * @param ... Arguments to use when filling the format string for printing.
 */
void guac_client_log_info(guac_client* client, const char* format, ...);

/**
 * Logs an error message in the log used by the given client. The logger
 * used will normally be defined by guacd (or whichever program loads the
 * proxy client) by setting the logging handlers of the client when it is
 * loaded.
 *
 * @param client The proxy client to log an error for.
 * @param format A printf-style format string to log.
 * @param ... Arguments to use when filling the format string for printing.
 */
void guac_client_log_error(guac_client* client, const char* format, ...);

/**
 * Logs an informational message in the log used by the given client. The
 * logger used will normally be defined by guacd (or whichever program loads
 * the proxy client) by setting the logging handlers of the client when it is
 * loaded.
 *
 * @param client The proxy client to log an informational message for.
 * @param format A printf-style format string to log.
 * @param ap The va_list containing the arguments to be used when filling the
 *           format string for printing.
 */
void vguac_client_log_info(guac_client* client, const char* format, va_list ap);

/**
 * Logs an error message in the log used by the given client. The logger
 * used will normally be defined by guacd (or whichever program loads the
 * proxy client) by setting the logging handlers of the client when it is
 * loaded.
 *
 * @param client The proxy client to log an error for.
 * @param format A printf-style format string to log.
 * @param ap The va_list containing the arguments to be used when filling the
 *           format string for printing.
 */
void vguac_client_log_error(guac_client* client, const char* format, va_list ap);

/**
 * Signals the given client to stop gracefully. This is a completely
 * cooperative signal, and can be ignored by the client or the hosting
 * daemon.
 *
 * @param client The proxy client to signal to stop.
 */
void guac_client_stop(guac_client* client);

/**
 * The default Guacamole client layer, layer 0.
 */
extern const guac_layer* GUAC_DEFAULT_LAYER;

#endif
