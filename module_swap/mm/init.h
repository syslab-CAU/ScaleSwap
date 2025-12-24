#ifndef __INIT_H
#define __INIT_H

struct Node_info {
	int min;
	int max;
};

extern struct Node_info *node_infos;

extern void init_node_infos(void);

#endif // __INIT_H
