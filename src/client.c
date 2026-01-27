static void authenticate (ssh_session session)
{
    int auth_code;

    printf("authenticating connection\ntrying authentication method: none\n");
    auth_code = ssh_userauth_none(session, NULL);
    switch (auth_code)
    {
        case SSH_AUTH_SUCCESS:
            printf("authentication succeeded:\n");
            return;
        case SSH_AUTH_DENIED: //fallthrough
        default:
            printf("authentication failed:\n");
    }

    int supported_auth_methods = ssh_userauth_list(session, NULL);
    int method_pubkey   = SSH_AUTH_METHOD_PUBLICKEY  & supported_auth_methods;
    int method_password = SSH_AUTH_METHOD_PASSWORD   & supported_auth_methods;
    int method_gssapi   = SSH_AUTH_METHOD_GSSAPI_MIC & supported_auth_methods;

    if (method_gssapi)
    {
        printf("trying authentication method: gssapi\n");
        auth_code = ssh_userauth_gssapi(session);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                printf("authentication succeeded:\n");
                return;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                printf("authentication failed:\n");
        }
    } 
    if (method_pubkey)
    {
        printf("trying authentication method: ssh key\n");
        auth_code = ssh_userauth_publickey_auto(session, NULL, NULL);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                printf("authentication succeeded:\n");
                return;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                printf("authentication failed:\n");
        }
    } 
    if (method_password)
    {
        printf("trying authentication method: password\n");
        char *password = getpass("password: ");
        auth_code = ssh_userauth_password(session, NULL, password);
        switch (auth_code)
        {
            case SSH_AUTH_SUCCESS:
                printf("authentication succeeded:\n");
                return;
            case SSH_AUTH_DENIED: //fallthrough
            default:
                printf("authentication failed:\n");
        }
    } 

    printf("no authentication possible\n");
}

ssh_session connect_to_host (const char *username, const char *host_addr)
{
    int err;

    ssh_session session = ssh_new();
    assert(session && "error: could not create ssh session.");

    err = ssh_options_set(session, SSH_OPTIONS_HOST, (void *)host_addr);
    assert(err == 0 && "setting host option was not successful");

    err = ssh_options_set(session, SSH_OPTIONS_USER, (void *)username);
    assert(err == 0 && "setting username option was not successful");

    err = ssh_connect(session);
    assert(err == SSH_OK && "something went wrong creating ssh connection");

    enum ssh_known_hosts_e known_host_status = ssh_session_has_known_hosts_entry(session);
    assert(known_host_status == SSH_KNOWN_HOSTS_OK);

    authenticate(session);
    return session;
}

ssh_channel open_channel(ssh_session session)
{
    int err;
    char *host;
    const int local_port = 9999;
    const int remote_port = 5000;

    ssh_channel channel = ssh_channel_new(session);
    assert(channel && "error: could not create ssh channel.");

    err = ssh_options_get(session, SSH_OPTIONS_HOST, &host);
    assert(err == SSH_OK && "error: reading host name was not successful");

    printf("trying to connect to host: %s\n", host);
    err = ssh_channel_open_forward(channel, host, remote_port, "localhost", local_port);

    if (err != SSH_OK)
    {
        fprintf(stderr, "error: opening remote channel was not successful\n");
        fprintf(stderr, "reason: %s\n", ssh_get_error(session));
        abort();
    }

    ssh_string_free_char(host); 
    return channel;
}

void read_channel(ssh_channel channel)
{
    char buffer[128];
    buffer[127] = '\0';
    printf("reading data...\n");
    while(1)
    {
        ssh_channel_read(channel, buffer, sizeof(buffer)-1, 0);
        printf("%s\n", buffer);
    }

    ssh_channel_free(channel);
}

void write_channel(ssh_channel channel)
{
    char data[] = "Hello world";
    int bytes_written = ssh_channel_write(channel, data, sizeof(data));
    if (bytes_written < (int)sizeof(data))
    {
        fprintf(stderr, "issue in writing bytes: %d/%lu bytes written", bytes_written, sizeof(data));
    }
}
