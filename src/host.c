int read_port(int port)
{
    int err;
    int sock_fd = 0;
    int connection_fd = 0;
    struct sockaddr_in serv_addr;
    
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        perror("\nn socket creation error\n");
        goto err;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);


    err = inet_pton(AF_INET, "0.0.0.0", &serv_addr.sin_addr);
    if (err <= 0)
    {
        perror("\ninvalid address/ address not supported\n");
        goto err;
    }

    err = bind(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (err != 0)
    {
        perror("\nsocket binding failed\n");
        goto err;
    }

    const int q_len = 0;
    err = listen(sock_fd, q_len);
    if (err != 0)
    {
        perror("\nsocket listening failed\n");
        goto err;
    }

    connection_fd = accept(sock_fd, NULL, 0);

    if (connection_fd < 0)
    {
        perror("\naccepting connection failed\n");
        goto err;
    }

    unsigned char buffer[1024];
    buffer[1023] = '\0';
    size_t buffer_len = sizeof(buffer)-1;

    printf("Reading messages...\n");
    err = recv(connection_fd, buffer, buffer_len, 0);
    if (err < 0)
    {
        perror("\nreceiving data failed\n");
        goto err;
    }
    else 
    {
        printf("received %s\n", buffer);
    }

    shutdown(sock_fd, SHUT_WR);
    printf("closing socket.\n");
    close(sock_fd);
    return 0;

    err:
    shutdown(sock_fd, SHUT_WR);
    printf("closing socket.\n");
    close(sock_fd);
    return -1;
}
