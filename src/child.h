
#ifndef _child_h
#define _child_h

void child_send(int fd, short event, void *);
void child_queue(int fd, short event);
void child_expire();

#endif /* _child_h */
