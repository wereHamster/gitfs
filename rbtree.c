/*
 *  GITFS: Filesystem view of a GIT repository
 *  Copyright (C) 2005  Mitchell Blank Jr <mitch@sfgoth.com>
 *
 *  This program can be distributed under the terms of the GNU GPL.
 *  See the file COPYING.
 *
 *  rbtree.c -- Implementation of the classic Red-Black tree algorithm.
 *  I didn't like any of the free implementations I found on the net, so I
 *  wrote my own.  The code is really ugly because I use a lot of nasty
 *  pointer tricks to get the code size as small as possible.  Before
 *  you judge this code too harshly, run it through "gcc -S -DNDEBUG -O3"
 *  and look at the generated assembly
 */
#include "gitfs.h"
#include <stdio.h>
#include <string.h>

/* Helper functions to test the color of a node */
static inline int black(const struct rb_node *node)
{
	return node->priv.is_red == 0;
}
static inline int red(const struct rb_node *node)
{
	return node->priv.is_red != 0;
}
static inline int all_children_black(const struct rb_node *node)
{
	/*
	 * Note: RBNIL is black, so this works even if node has less
	 * than two children
	 */
	return (node->child[0]->priv.is_red |
		node->child[1]->priv.is_red) == 0;
}

/* Helper functions to set the color of a node */
static inline void set_black(struct rb_node *node)
{
	node->priv.is_red = 0;
}
static inline void set_red(struct rb_node *node)
{
	if (sizeof(node) <= sizeof(node->priv.is_red)) {
		/*
		 * Dirty little optimization trick -- we just need to set
		 * .is_red to anything non-zero.  Since we know node != NULL
		 * we just use that pointer since it's already in a
		 * register!
		 */
		node->priv.is_red = (unsigned int) node;
		assert(node->priv.is_red != 0);
	} else
		node->priv.is_red = 1;
}

/*
 * Given a pointer into the "child[]" array of a node, return a pointer to
 * the node itself.  Relies on the fact that all nodes are aligned to
 * RBNODE_ALIGN bytes
 */
static inline struct rb_node *childptr_to_node(struct rb_node **cptr)
{
	return (struct rb_node *)
			(((unsigned long) cptr) & ~(RBNODE_ALIGN - 1));
}

/* Given a node, returns its parent */
static inline struct rb_node *parent(struct rb_node *node)
{
	return childptr_to_node(node->priv.plink);
}

/*
 * This is the "sentinel" node - it is used instead of NULL to make some of
 * the special cases easier
 */
struct rb_node rb_NilNode = {
	.child = { RBNIL, RBNIL },
	.priv = {
		.plink = &RBNIL->child[0],
		.is_red = 0,
	},
};

/* Empty tree, suitable for memcpy() */
const struct rb_tree empty_rbtree = EMPTY_RBTREE;

/* The "aroot" node is the only one without a valid ->priv.plink */
#define IS_AROOT(node)	((node)->priv.plink == NULL)
#define IS_ROOT(node)	(IS_AROOT(parent(node)))

#define assert_node_ok(n)						\
do {									\
	assert((n) != NULL);						\
	assert((n) == childptr_to_node(&(n)->child[0]));		\
	assert((n) == childptr_to_node(&(n)->child[1]));		\
	assert(!RB_IS_NIL(n));						\
	assert((n)->priv.plink == NULL ||				\
	       *((n)->priv.plink) == (n));				\
} while (0)

/*
 * To keep the underlying pointer math as quick as possible, we always track
 * tree direction by remembering the number of bytes into the "child[]" array
 * we need to look to find the correct child
 */
enum rb_dir {
	LEFT_DIR = 0,
	RIGHT_DIR = (unsigned int)
			(((char *) &RBNIL->child[1]) -
			 ((char *) &RBNIL->child[0])),
};

/* Reverse a "enum rb_dir" value */
static inline enum rb_dir opposite(enum rb_dir d)
{
	return (enum rb_dir) (((unsigned int) RIGHT_DIR) - (unsigned int) d);
}

/* returns LEFT_DIR if we're our parent's left node, RIGHT_DIR otherwise */
static inline enum rb_dir treedir(const struct rb_node *node)
{
	return (enum rb_dir)
		  (((unsigned long) node->priv.plink) &
		    (unsigned long) RIGHT_DIR);
}

/* Returns "parent" when we know we're the left or right child */
static inline struct rb_node *parent_of_leftchild(struct rb_node *node)
{
	assert(treedir(node) == LEFT_DIR);
	return (struct rb_node *) node->priv.plink;
}
static inline struct rb_node *parent_of_rightchild(struct rb_node *node)
{
	assert(treedir(node) == RIGHT_DIR);
	return (struct rb_node *) (node->priv.plink - 1);
}

/*
 * Returns a pointer to the element of node->child[] associated with the
 * given "direction".  The child_dir() convinience macro also dereferences
 * this (i.e. returns a pointer to the actual child)
 */
static inline struct rb_node **childp_dir(struct rb_node *node,
					  enum rb_dir dir)
{
	return (struct rb_node **)
			(((char *) (&node->child[0]))
			 + (unsigned int) dir);
}
#define child_dir(node, dir)		(*childp_dir((node), (dir)))

/* Like childp_dir(), but returns the *opposite* child */
static inline struct rb_node **childp_opposite(struct rb_node *node,
					       enum rb_dir dir)
{
	return (struct rb_node **)
			(((char *) (&node->child[1]))
			 - (unsigned int) dir);
}
#define child_opposite(node, dir)	(*childp_opposite((node), (dir)))

/* Returns a pointer to where our sibling's pointer is stored */
static inline struct rb_node **siblingp(struct rb_node *node)
{
	return (struct rb_node **)
		  (((unsigned long) node->priv.plink) ^
		    (unsigned long) RIGHT_DIR);
}
#define sibling(node)			(*siblingp(node))

/* Do a 'tree rotate' transform around "node" */
static void rotate(struct rb_node *node, enum rb_dir dir)
{
	struct rb_node *oldchild, **childp;

	assert_node_ok(node);
	assert(dir == LEFT_DIR || dir == RIGHT_DIR);
	childp = childp_opposite(node, dir);
	oldchild = *childp;
	*childp = child_dir(oldchild, dir);
	if (!RB_IS_NIL(*childp))
		(*childp)->priv.plink = childp;
	assert(oldchild != RBNIL);
	*(oldchild->priv.plink = node->priv.plink) = oldchild;
	*(node->priv.plink = childp_dir(oldchild, dir)) = node;
}

/* Inserts new node at location given by "link" and rebalances tree */
void rbtree_insert(struct rb_node **link, struct rb_node *node)
{
	struct rb_node *pnode;

	assert_node_ok(childptr_to_node(link));
	assert(node != NULL);
	assert(!RB_IS_NIL(node));
	assert(RB_IS_NIL(*link));

	/* Do normal insert here */
	*link = node;
	node->child[0] = node->child[1] = RBNIL;
	node->priv.plink = link;
	set_red(node);

	/* Now the tricky part - rebalancing the tree around "node" */
	for (;;) {
		struct rb_node *uncle;

		assert_node_ok(node);
		assert(red(node));
		/*
		 * If our parent is BLACK, then we're done fixing - node that
		 * this is also true if we're at the root
		 */
		pnode = parent(node);
		if (black(pnode))
			break;
		/* Since our root is BLACK, parent isn't root either */
		assert(!IS_ROOT(node));
		assert(!IS_ROOT(pnode));
		uncle = sibling(pnode);
		if (red(uncle)) {
			/* Make parent's color BLACK and move up two */
			set_black(pnode);
			set_black(uncle);
			node = parent(pnode);
			assert(!RB_IS_NIL(node));
			set_red(node);
		} else {
			enum rb_dir parentdir = treedir(pnode);
			/* If "node" isn't in same dir as parent, switch */
			if (treedir(node) != parentdir) {
				node = pnode;
				rotate(node, parentdir);
				pnode = parent(node);
			}
			assert(treedir(node) == parentdir);
			/* Now we can re-color and rotate toward uncle */
			set_black(pnode);
			pnode = parent(pnode);
			assert(!RB_IS_NIL(pnode));
			set_red(pnode);
			rotate(pnode, opposite(parentdir));
		}
	}

	/* we might have recolored the root node - fix that */
	assert(red(node));
	if (IS_AROOT(pnode)) {
		assert(IS_ROOT(node));
		set_black(node);
	}
}

/* link parent's "dir" child to "child" node */
static inline void rb_make_link(struct rb_node *parent, enum rb_dir dir,
				struct rb_node *child)
{
	struct rb_node **cp = childp_dir(parent, dir);

	if (!RB_IS_NIL(child))
		child->priv.plink = cp;
	*cp = child;
}

/* Deletes a node and rebalances the tree */
void rbtree_delete(struct rb_node *node)
{
	struct rb_node *pn, *cn;
	int is_black;

	assert_node_ok(node);
	if (RB_IS_NIL(node->child[0])) {
		cn = node->child[1];
		/* note: cn may be RBNIL here now - that's ok */
		goto less_than_two_children;
	} else if (RB_IS_NIL(node->child[1])) {
		cn = node->child[0];
	    less_than_two_children:
		pn = parent(node);
		is_black = black(node);
		/* Remove this entry */
		rb_make_link(pn, treedir(node), cn);
	} else {
		struct rb_node *next;
		/*
		 * If the node we're going to delete has two children we have
		 * to shuffle things around first
		 *
		 * The next larger node after will be on our right side and
		 * then down the left slope
		 */
		for (next = node->child[1]; !RB_IS_NIL(next->child[0]); )
			next = next->child[0];
		assert_node_ok(next);
		assert(next != node);
		/*
		 * We need to move this node where 'node' used to be in the
		 * tree - and we'll use its color for recalculation
		 */
		is_black = black(next);
		pn = parent(next);
		assert(!RB_IS_NIL(pn));
		cn = next->child[1];
		/* Now remove the "next" node */
		rb_make_link(pn, treedir(next), cn);
		/* Now put "next" where "node" use to be */
		memcpy(next, node, sizeof(*next));
		/* Since "pn" may be pointing at the old node, fix it... */
		if (pn == node)
			pn = next;
		/* Finally, link node's old parent to next */
		child_dir(parent(next), treedir(node)) = next;
		/* ...and our child nodes to us */
		assert(!RB_IS_NIL(next->child[0]));
		next->child[0]->priv.plink = &next->child[0];
		if (!RB_IS_NIL(next->child[1]))
			next->child[1]->priv.plink = &next->child[1];
		assert(RB_IS_NIL(cn) || parent(cn) == pn);
	}

	/* If the place we removed was black we may need to fix tree */
	if (is_black) {
		assert(!RB_IS_NIL(pn));
		assert(RB_IS_NIL(cn) || !RB_IS_NIL(parent(cn)));
		assert(RB_IS_NIL(cn) || parent(cn) == pn);
		while (black(cn) && !IS_AROOT(pn)) {
			enum rb_dir dir;
			struct rb_node *sibnode;
			assert(RB_IS_NIL(cn) || !RB_IS_NIL(parent(cn)));
			assert(RB_IS_NIL(cn) || parent(cn) == pn);
			/*
			 * Unfortunately we can't use treedir(cn) here
			 * because cn could be RBNIL
			 */
			dir = (pn->child[0] == cn) ? LEFT_DIR : RIGHT_DIR;
			assert(RB_IS_NIL(cn) || dir == treedir(cn));
			sibnode = child_opposite(pn, dir);
			if (red(sibnode)) {
				assert(!RB_IS_NIL(sibnode));
				set_black(sibnode);
				assert(!RB_IS_NIL(pn));
				set_red(pn);
				rotate(pn, dir);
				sibnode = child_opposite(pn, dir);
			}
			if (all_children_black(sibnode)) {
				assert(!RB_IS_NIL(sibnode));
				set_red(sibnode);
				assert(!RB_IS_NIL(parent(pn)));
				cn = pn;
				pn = parent(pn);
			} else {
				if (black(child_opposite(sibnode, dir))) {
					struct rb_node *sch;
					assert(!RB_IS_NIL(sibnode));
					sch = child_dir(sibnode, dir);
					assert(!RB_IS_NIL(sch));
					set_black(sch);
					set_red(sibnode);
					rotate(sibnode, opposite(dir));
					sibnode = child_opposite(pn, dir);
				}
				sibnode->priv.is_red = pn->priv.is_red;
				set_black(pn);
				cn = child_opposite(sibnode, dir);
				assert(!RB_IS_NIL(cn));
				set_black(cn);
				rotate(pn, dir);
				return;
			}
		}
		set_black(cn);
	}
}

/* Returns first node in tree or NULL if tree is empty */
struct rb_node *rbtree_first(struct rb_tree *tree)
{
	struct rb_node *node = tree->aroot.child[0];

	if (RB_IS_NIL(node))
		return NULL;
	for (;;) {
		struct rb_node *next = node->child[0];
		if (RB_IS_NIL(next))
			break;
		node = next;
	}
	return node;
}

struct rb_node *rbtree_next(struct rb_node *node)
{
	struct rb_node *next = node->child[1];

	if (!RB_IS_NIL(next)) {
		/*
		 * We have a right-child; follow down its left path for the
		 * next node
		 */
		do {
			node = next;
			next = node->child[0];
		} while (!RB_IS_NIL(next));
	} else {
		/* Find an ancestor that we're on the left side of */
		while (treedir(node) == RIGHT_DIR)
			node = parent_of_rightchild(node);
		node = parent_of_leftchild(node);
		if (IS_AROOT(node))
			node = NULL;	/* end of iteration */
	}
	return node;
}

#ifdef RBTREE_UNITTEST

#include <stdlib.h>

static int rbtree_check_dblred(struct rb_node *node)
{
	int saw_errors = 0;
	unsigned int i;

	if (RB_IS_NIL(node))
		return 0;
	assert_node_ok(node);
	if (red(node))
		for (i = 0; i < 2; i++)
			if (red(node->child[i])) {
				fprintf(stderr, "Node %p has child #%u "
					"(%p), both red!\n", node, i,
					node->child[i]);
				saw_errors++;
			}
	for (i = 0; i < 2; i++)
		saw_errors += rbtree_check_dblred(node->child[i]);
	return saw_errors;
}

struct rb_test {
	struct rb_node rb;	/* must be first! */
	int in_tree;
	unsigned long val;
};

static inline unsigned long rbtest_nodeval(struct rb_node *node)
{
	return ((struct rb_test *) node)->val;
}

struct rb_count_state {
	unsigned int min, max, total;
	unsigned long minval, maxval;
};

static void rbtree_count(struct rb_node *node, struct rb_count_state *mm,
			 int black_only)
{
	struct rb_count_state c[2];
	unsigned int i;
	unsigned long nodeval;

	if (RB_IS_NIL(node)) {
		mm->min = mm->max = mm->total = 0;
		return;
	}
	assert_node_ok(node);
	for (i = 0; i < 2; i++) {
		rbtree_count(node->child[i], &c[i], black_only);
		assert(c[i].min <= c[i].max);
		assert(c[i].min <= c[i].total);
		assert(c[i].max <= c[i].total);
	}
	mm->min = (c[0].min < c[1].min) ? c[0].min : c[1].min;
	mm->max = (c[0].max > c[1].max) ? c[0].max : c[1].max;
	mm->total = c[0].total + c[1].total;
	assert(mm->min <= mm->max);
	if (black_only == 0 || black(node)) {
		mm->min++;
		mm->max++;
	}
	mm->total++;
	mm->minval = mm->maxval = nodeval = rbtest_nodeval(node);
	if (c[0].total != 0) {
		assert(c[0].minval <= c[0].maxval);
		assert(c[0].maxval <= nodeval);
		mm->minval = c[0].minval;
	}
	if (c[1].total != 0) {
		assert(c[1].minval <= c[1].maxval);
		assert(c[1].minval >= nodeval);
		mm->maxval = c[1].maxval;
	}
	assert(mm->minval <= mm->maxval);
}

static unsigned int rbtree_count_by_iteration(struct rb_tree *tree)
{
	unsigned int result = 0;
	struct rb_node *node = rbtree_first(tree);

	while (node != NULL) {
		result++;
		node = rbtree_next(node);
	}
	return result;
}

static const struct rb_node *rbtest_last_node;
static const char *rbtest_last_op;

static void rbtree_full_check(struct rb_tree *tree, unsigned int size)
{
	struct rb_count_state mm;
	struct rb_node *root = tree->aroot.child[0];
	int saw_errors = 0;

	if (RB_IS_NIL(root)) {
		if (size != 0) {
			mm.total = 0;
			goto size_error;
		}
		return;		/* empty tree is fine */
	}
	assert_node_ok(root);
	if (red(root)) {
		fprintf(stderr, "root at %p is not black\n", root);
		saw_errors++;
	}
	saw_errors += rbtree_check_dblred(root);
	rbtree_count(root, &mm, 1);
	if (mm.min != mm.max) {
		fprintf(stderr, "differing number of black nodes from "
			"root %p (min %u, max %u)\n", root, mm.min, mm.max);
		saw_errors++;
	}
	if (mm.total != size) {
	   size_error:
		fprintf(stderr, "expected %u items in tree, saw %u\n",
			size, mm.total);
		saw_errors++;
	}
	mm.total = rbtree_count_by_iteration(tree);
	if (mm.total != size) {
		fprintf(stderr, "expected %u items in tree, iterated %u\n",
			size, mm.total);
		saw_errors++;
	}
	if (saw_errors == 0)
		return;
	fprintf(stderr, "root at %p had %u error(s), last op was %s %p\n",
		root, saw_errors, rbtest_last_op, rbtest_last_node);
	abort();
}

static void rbtree_print_stats(struct rb_tree *tree)
{
	struct rb_count_state mm;

	rbtree_count(tree->aroot.child[0], &mm, 0);
	fprintf(stderr, "  (tree has %u elements; paths range from %u-%u "
		"nodes)\n", mm.total, mm.min, mm.max);

}

static struct rb_test *testdata;
static unsigned int test_size;

static void rbtest_setup(int count)
{
	unsigned int i, mask;

	testdata = malloc(count * sizeof(testdata[0]));
	if (testdata == NULL) {
		fprintf(stderr, "couldn't allocate space for %d elements\n",
			count);
		abort();
	}
	test_size = count;
	/* find smallest mask that will fit "test_size" bits */
	mask = 0;
	while (mask < test_size)
		mask = (mask << 1) | 1;
	mask = ~mask;
	for (i = 0; i < test_size; i++) {
		/* this ensures that each .val is unique */
		testdata[i].val = (random() & mask) | i;
		testdata[i].in_tree = 0;
	}
}

static struct rb_tree test_tree = EMPTY_RBTREE;
static unsigned int items_in_tree = 0;

static void rbtest_insert(struct rb_test *rt)
{
	struct rb_node **link;

	assert(rt->in_tree == 0);
	rbtree_walk(&test_tree, link) {
		unsigned long pval = rbtest_nodeval(*link);
		if (pval == rt->val) {
			fprintf(stderr, "insert failed: val %lu already "
				"found at node %p (testdata = %p)\n",
				pval, *link, rt);
			abort();
		}
		link = &(*link)->child[(rt->val < pval) ? 0 : 1];
	}
	rbtree_insert(link, &rt->rb);
	assert(RB_IS_NIL(test_tree.aroot.child[1]));
	rt->in_tree = 1;
	items_in_tree++;
	rbtest_last_op = "insert";
	rbtest_last_node = &rt->rb;
}

static void rbtest_delete(struct rb_test *rt)
{
	struct rb_node **nodep;

	assert(rt->in_tree != 0);
	rbtree_walk(&test_tree, nodep) {
		unsigned long nval = rbtest_nodeval(*nodep);
		if (nval == rt->val)
			goto got_node;
		nodep = &(*nodep)->child[(rt->val < nval) ? 0 : 1];
	}
	fprintf(stderr, "delete failed: couldn't find val %lu\n", rt->val);
	abort();
    got_node:
	assert(*nodep == &rt->rb);
	rbtree_delete(*nodep);
	assert(RB_IS_NIL(test_tree.aroot.child[1]));
	rt->in_tree = 0;
	items_in_tree--;
	rbtest_last_op = "delete";
	rbtest_last_node = &rt->rb;
}

int main(int argn, char **argv)
{
	unsigned int i, rcount;
	unsigned long last_val = 0;

	(void) argn;
	if (argv[1] == NULL || argv[2] == NULL || argv[3] != NULL) {
		fprintf(stderr, "usage: %s NUM_ELEM RUN_COUNT\n", argv[0]);
		return 8;
	}
	rbtest_setup(atoi(argv[1]));
	srandom(getpid() ^ time(NULL));
	/* Phase 1: insert half the elements into the array */
	fprintf(stderr, "Phase 1...\n");
	for (i = 0; i < test_size; i++)
		if ((random() & 1) != 0) {
			rbtest_insert(&testdata[i]);
			rbtree_full_check(&test_tree, items_in_tree);
		}
	rbtree_print_stats(&test_tree);
	/* Phase 2: do random insert/deletes */
	fprintf(stderr, "Phase 2...\n");
	rcount = atoi(argv[2]);
	for (i = 0; i < rcount; i++) {
		struct rb_test *rt;
		rt = &testdata[(random() + last_val) % test_size];
		last_val = rt->val;
		if (rt->in_tree == 0)
			rbtest_insert(rt);
		else
			rbtest_delete(rt);
		rbtree_full_check(&test_tree, items_in_tree);
	}
	rbtree_print_stats(&test_tree);
	/* Phase 3: delete everything in the tree */
	fprintf(stderr, "Phase 3...\n");
	for (i = 0; i < test_size; i++) {
		struct rb_test *rt = &testdata[i];
		if (rt->in_tree == 0)
			continue;
		rbtest_delete(rt);
		rbtree_full_check(&test_tree, items_in_tree);
	}
	rbtree_print_stats(&test_tree);
	assert(RB_IS_NIL(test_tree.aroot.child[0]));
	/*
	 * Phase 4: check for edge cases by repeatedly adding a few elements
	 * and then deleting them in a different order
	 */
	fprintf(stderr, "Phase 4...\n");
#define FEW_ELEMENTS		(7U)
	for (i = 0; i < rcount; i++) {
		struct rb_test *rts[FEW_ELEMENTS], *trt;
		unsigned int j, nelem = random() % FEW_ELEMENTS;
		if (nelem > test_size)
			nelem = test_size;
		for (j = 0; j < nelem; j++) {
			do {
				rts[j] = &testdata[(random() + last_val) %
						test_size];
				last_val = rts[j]->val;
			} while (rts[j]->in_tree != 0);
			rbtest_insert(rts[j]);
			rbtree_full_check(&test_tree, items_in_tree);
		}
		for (j = 0; j < nelem; j++) {
			unsigned int swap_with = random() % nelem;
			trt = rts[j];
			rts[j] = rts[swap_with];
			rts[swap_with] = trt;
		}
		for (j = 0; j < nelem; j++) {
			assert(rts[j]->in_tree != 0);
			rbtest_delete(rts[j]);
			rbtree_full_check(&test_tree, items_in_tree);
		}
		assert(RB_IS_NIL(test_tree.aroot.child[0]));
	}
	rbtree_print_stats(&test_tree);
	return 0;
}

#endif /* RBTREE_UNITTEST */
