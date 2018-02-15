#include <switch.h>

#define UNICAST_PARAMS (4)
#define UNICAST_SYNTAX "<uuid> <start|stop> [<remote_ip> <remote_port>]"

SWITCH_STANDARD_API(unicast_api_main);
SWITCH_MODULE_LOAD_FUNCTION(mod_unicast_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_unicast_shutdown);
SWITCH_MODULE_DEFINITION(mod_unicast, mod_unicast_load, mod_unicast_shutdown, NULL);

struct unicast_pvt_t
{
	switch_channel_t *channel;
	char *remote_ip;
	char *local_ip;
	switch_port_t remote_port;
	switch_port_t local_port;
	switch_socket_t *sock;
	switch_sockaddr_t *remote_addr;
};

static switch_bool_t unicast_session_media_bug_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	if (type != SWITCH_ABC_TYPE_READ && type != SWITCH_ABC_TYPE_CLOSE)
	{
		return SWITCH_TRUE;
	}

	struct unicast_pvt_t* esp = (struct unicast_pvt_t *) user_data;
	switch_core_session_t *session = switch_core_media_bug_get_session(bug);

	if (type == SWITCH_ABC_TYPE_READ)
	{
		switch_frame_t raw_frame = { 0 };
		uint8_t data[SWITCH_RECOMMENDED_BUFFER_SIZE] = { 0 };
		switch_size_t bytes;
		raw_frame.data = data;
		raw_frame.buflen = SWITCH_RECOMMENDED_BUFFER_SIZE;

		if (switch_core_media_bug_read(bug, &raw_frame, SWITCH_FALSE) != SWITCH_STATUS_SUCCESS)
		{
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Something is wrong in reading frame\n");
			return SWITCH_FALSE;
		}

		if (raw_frame.samples == 0)
		{
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "packet is empty\n");
			return SWITCH_TRUE;
		}

		bytes = raw_frame.datalen;

		switch_status_t status = switch_socket_sendto(esp->sock, esp->remote_addr, 0, (void *) raw_frame.data, &bytes);

		if (status != SWITCH_STATUS_SUCCESS)
		{
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Unable to send packet : %d\n", status);
			return SWITCH_TRUE;
		}

		return SWITCH_TRUE;
	}

	switch_channel_set_private(esp->channel, "_unicast_bug_", NULL);
	switch_socket_shutdown(esp->sock, SWITCH_SHUTDOWN_READWRITE);
	switch_socket_close(esp->sock);
	switch_rtp_release_port(esp->local_ip, esp->local_port);

	esp->channel = NULL;
	esp->local_port = 0;
	esp->remote_port = 0;
	esp->local_ip = NULL;
	esp->remote_ip = NULL;
	esp->remote_addr = NULL;
	esp->sock = NULL;
	esp = NULL;

	return SWITCH_TRUE;
}

static switch_status_t unicast_start(switch_core_session_t *session, char *remote_ip, switch_port_t remote_port)
{
	if (!session)
	{
		return SWITCH_STATUS_FALSE;
	}

	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_media_bug_t *bug = NULL;
	switch_memory_pool_t *pool = switch_core_session_get_pool(session);
	char local_ip[256];
	switch_sockaddr_t *local_addr;
	struct unicast_pvt_t *user_data = NULL;
	int mask = 0;

	user_data = switch_core_session_alloc(session, sizeof(*user_data));
	user_data->channel = channel;
	user_data->remote_ip = remote_ip;
	user_data->remote_port = remote_port;

	if ((switch_find_local_ip(local_ip, sizeof(local_ip), &mask, AF_INET)) != SWITCH_STATUS_SUCCESS)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to locate source IP setting it to localhost\n");
		return SWITCH_STATUS_FALSE;
	}

	user_data->local_ip = local_ip;

	if (!(user_data->local_port = switch_rtp_request_port(user_data->local_ip)))
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to allocate a local RTP port\n");
		return SWITCH_STATUS_FALSE;
	}

	if (switch_sockaddr_info_get(&local_addr, user_data->local_ip, SWITCH_UNSPEC, user_data->local_port, 0, pool) != SWITCH_STATUS_SUCCESS)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Local Address Error!");
		return SWITCH_STATUS_FALSE;
	}

	if (switch_sockaddr_info_get(&user_data->remote_addr, user_data->remote_ip, SWITCH_UNSPEC, user_data->remote_port, 0, pool) != SWITCH_STATUS_SUCCESS)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Remote Address Error!");
		return SWITCH_STATUS_FALSE;
	}

	if (switch_socket_create(&user_data->sock, AF_INET, SOCK_DGRAM, 0, pool) != SWITCH_STATUS_SUCCESS)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to create a socket\n");
		return SWITCH_STATUS_FALSE;
	}

	if (switch_socket_bind(user_data->sock, local_addr) != SWITCH_STATUS_SUCCESS)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Local Address Bind Error!");
		return SWITCH_STATUS_FALSE;
	}

	if (switch_core_media_bug_add(session, "unicast", NULL, unicast_session_media_bug_callback, user_data, 0, SMBF_READ_STREAM, &bug) != SWITCH_STATUS_SUCCESS)
	{
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Cannot attach bug\n");
		return SWITCH_STATUS_FALSE;
	}

	switch_channel_set_private(channel, "_unicast_bug_", bug);

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_unicast_load)
{
	switch_api_interface_t *api_interface;

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_API(api_interface, "uuid_unicast", "stream the audio to a remote endpoint", unicast_api_main, UNICAST_SYNTAX);

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_unicast_shutdown)
{
	return SWITCH_STATUS_UNLOAD;
}

SWITCH_STANDARD_API(unicast_api_main)
{
	switch_core_session_t *unicast_session = NULL;
	switch_media_bug_t *bug;
	switch_channel_t *channel;

	int argc;
	char *argv[UNICAST_PARAMS];
	char *cmd_rw, *uuid, *command, *remote_ip;
	switch_port_t remote_port;

	if (zstr(cmd))
	{
		stream->write_function(stream, "-USAGE: %s\n", UNICAST_SYNTAX);
		return SWITCH_STATUS_SUCCESS;
	}

	cmd_rw = strdup(cmd);

	argc = switch_separate_string(cmd_rw, ' ', argv, UNICAST_PARAMS);

	if (argc != 2 && argc != 4)
	{
		stream->write_function(stream, "-USAGE: %s\n", UNICAST_SYNTAX);
		goto end;
	}

	uuid = argv[0];
	command = argv[1];

	unicast_session = switch_core_session_locate(uuid);

	if (!unicast_session)
	{
		stream->write_function(stream, "Cannot find the session with the given uuid -USAGE: %s\n", UNICAST_SYNTAX);
		goto end;
	}

	channel = switch_core_session_get_channel(unicast_session);
	bug = (switch_media_bug_t *) switch_channel_get_private(channel, "_unicast_bug_");

	if (bug)
	{
		if (strncasecmp(command, "stop", sizeof("stop") - 1) == 0)
		{
			switch_core_media_bug_remove(unicast_session, &bug);
			switch_channel_set_private(channel, "_unicast_bug_", NULL);
			stream->write_function(stream, "+OK\n");
			goto end;
		}

		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "Already running on channel.\n");
		goto end;
	}

	if (strncasecmp(command, "start", sizeof("start") - 1) != 0)
	{
		stream->write_function(stream, "incorrect -USAGE: %s\n", UNICAST_SYNTAX);
		goto end;
	}

	if (argc != 4)
	{
		stream->write_function(stream, "-USAGE: %s\n", UNICAST_SYNTAX);
		goto end;
	}

	remote_ip = argv[2];
	remote_port = (switch_port_t) atoi(argv[3]);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "remote_ip= %s; remote_port = %d; uuid = %s\n", remote_ip, remote_port, uuid);

	if (unicast_start(unicast_session, remote_ip, remote_port) != SWITCH_STATUS_SUCCESS)
	{
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Failure starting unicast_session.\n");
		goto end;
	}

	stream->write_function(stream, "+OK\n");

end:
	if (unicast_session)
	{
		switch_core_session_rwunlock(unicast_session);
	}

	return SWITCH_STATUS_SUCCESS;
}