#include "ui.h"
#include "jaa.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

job g_job;

void *ui_loop()
{
    jaa_ui_create();
    while(!jaa_ui_should_shutdown())
    {
        jaa_ui_update(g_job);
    }
    return NULL;
}

void *job_loop()
{
    jaa_job_init(&g_job);
    while(1)
    {
        jaa_job_update(g_job);
        if(jaa_job_should_shutdown(g_job))
            break;
    }
    return NULL;
}

int main(void)
{
    g_job = jaa_job_create();

    pthread_t job_thread;
    pthread_t ui_thread;
    pthread_create(&job_thread, NULL, job_loop, NULL);
    pthread_create(&ui_thread, NULL, ui_loop, NULL);
    pthread_join(ui_thread, NULL);

    jaa_ui_destroy();
    jaa_job_destroy(g_job);
    return 0;
}
