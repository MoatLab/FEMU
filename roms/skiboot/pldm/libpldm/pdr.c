#include "pdr.h"
#include <pldm/include/libpldm/platform.h>
#include <assert.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>

typedef struct pldm_pdr_record {
	uint32_t record_handle;
	uint32_t size;
	uint8_t *data;
	struct pldm_pdr_record *next;
	bool is_remote;
	uint16_t terminus_handle;
} pldm_pdr_record;

typedef struct pldm_pdr {
	uint32_t record_count;
	uint32_t size;
	pldm_pdr_record *first;
	pldm_pdr_record *last;
} pldm_pdr;

static inline uint32_t get_next_record_handle(const pldm_pdr *repo,
					      const pldm_pdr_record *record)
{
	assert(repo != NULL);
	assert(record != NULL);

	if (record == repo->last) {
		return 0;
	}
	return record->next->record_handle;
}

static void add_record(pldm_pdr *repo, pldm_pdr_record *record)
{
	assert(repo != NULL);
	assert(record != NULL);

	if (repo->first == NULL) {
		assert(repo->last == NULL);
		repo->first = record;
		repo->last = record;
	} else {
		repo->last->next = record;
		repo->last = record;
	}
	repo->size += record->size;
	++repo->record_count;
}

static inline uint32_t get_new_record_handle(const pldm_pdr *repo)
{
	assert(repo != NULL);
	uint32_t last_used_hdl =
		repo->last != NULL ? repo->last->record_handle : 0;
	assert(last_used_hdl != UINT32_MAX);

	return last_used_hdl + 1;
}

static pldm_pdr_record *make_new_record(const pldm_pdr *repo,
					const uint8_t *data, uint32_t size,
					uint32_t record_handle, bool is_remote,
					uint16_t terminus_handle)
{
	assert(repo != NULL);
	assert(size != 0);

	pldm_pdr_record *record = malloc(sizeof(pldm_pdr_record));
	assert(record != NULL);
	record->record_handle = record_handle == 0 ?
					get_new_record_handle(repo) :
					record_handle;
	record->size = size;
	record->is_remote = is_remote;
	record->terminus_handle = terminus_handle;
	if (data != NULL) {
		record->data = malloc(size);
		assert(record->data != NULL);
		memcpy(record->data, data, size);
		/* If record handle is 0, that is an indication for this API to
		 * compute a new handle. For that reason, the computed handle
		 * needs to be populated in the PDR header. For a case where the
		 * caller supplied the record handle, it would exist in the
		 * header already.
		 */
		if (!record_handle) {
			struct pldm_pdr_hdr *hdr =
				(struct pldm_pdr_hdr *)(record->data);
			hdr->record_handle = htole32(record->record_handle);
		}
	}
	record->next = NULL;

	return record;
}

uint32_t pldm_pdr_add(pldm_pdr *repo, const uint8_t *data, uint32_t size,
		      uint32_t record_handle, bool is_remote,
		      uint16_t terminus_handle)
{
	assert(size != 0);
	assert(data != NULL);

	pldm_pdr_record *record = make_new_record(
		repo, data, size, record_handle, is_remote, terminus_handle);
	add_record(repo, record);

	return record->record_handle;
}

pldm_pdr *pldm_pdr_init(void)
{
	pldm_pdr *repo = malloc(sizeof(pldm_pdr));
	assert(repo != NULL);
	repo->record_count = 0;
	repo->size = 0;
	repo->first = NULL;
	repo->last = NULL;

	return repo;
}

void pldm_pdr_destroy(pldm_pdr *repo)
{
	assert(repo != NULL);

	pldm_pdr_record *record = repo->first;
	while (record != NULL) {
		pldm_pdr_record *next = record->next;
		if (record->data) {
			free(record->data);
			record->data = NULL;
		}
		free(record);
		record = next;
	}
	free(repo);
}

const pldm_pdr_record *pldm_pdr_find_record(const pldm_pdr *repo,
					    uint32_t record_handle,
					    uint8_t **data, uint32_t *size,
					    uint32_t *next_record_handle)
{
	assert(repo != NULL);
	assert(data != NULL);
	assert(size != NULL);
	assert(next_record_handle != NULL);

	if (!record_handle && (repo->first != NULL)) {
		record_handle = repo->first->record_handle;
	}
	pldm_pdr_record *record = repo->first;
	while (record != NULL) {
		if (record->record_handle == record_handle) {
			*size = record->size;
			*data = record->data;
			*next_record_handle =
				get_next_record_handle(repo, record);
			return record;
		}
		record = record->next;
	}

	*size = 0;
	*next_record_handle = 0;
	return NULL;
}

const pldm_pdr_record *
pldm_pdr_get_next_record(const pldm_pdr *repo,
			 const pldm_pdr_record *curr_record, uint8_t **data,
			 uint32_t *size, uint32_t *next_record_handle)
{
	assert(repo != NULL);
	assert(curr_record != NULL);
	assert(data != NULL);
	assert(size != NULL);
	assert(next_record_handle != NULL);

	if (curr_record == repo->last) {
		*data = NULL;
		*size = 0;
		*next_record_handle = get_next_record_handle(repo, curr_record);
		return NULL;
	}

	*next_record_handle = get_next_record_handle(repo, curr_record->next);
	*data = curr_record->next->data;
	*size = curr_record->next->size;
	return curr_record->next;
}

const pldm_pdr_record *
pldm_pdr_find_record_by_type(const pldm_pdr *repo, uint8_t pdr_type,
			     const pldm_pdr_record *curr_record, uint8_t **data,
			     uint32_t *size)
{
	assert(repo != NULL);

	pldm_pdr_record *record = repo->first;
	if (curr_record != NULL) {
		record = curr_record->next;
	}
	while (record != NULL) {
		struct pldm_pdr_hdr *hdr = (struct pldm_pdr_hdr *)record->data;
		if (hdr->type == pdr_type) {
			if (data && size) {
				*size = record->size;
				*data = record->data;
			}
			return record;
		}
		record = record->next;
	}

	if (size) {
		*size = 0;
	}
	return NULL;
}

uint32_t pldm_pdr_get_record_count(const pldm_pdr *repo)
{
	assert(repo != NULL);

	return repo->record_count;
}

uint32_t pldm_pdr_get_repo_size(const pldm_pdr *repo)
{
	assert(repo != NULL);

	return repo->size;
}

uint32_t pldm_pdr_get_record_handle(const pldm_pdr *repo,
				    const pldm_pdr_record *record)
{
	assert(repo != NULL);
	assert(record != NULL);

	return record->record_handle;
}

inline bool pldm_pdr_record_is_remote(const pldm_pdr_record *record)
{
	assert(record != NULL);

	return record->is_remote;
}

uint32_t pldm_pdr_add_fru_record_set(pldm_pdr *repo, uint16_t terminus_handle,
				     uint16_t fru_rsi, uint16_t entity_type,
				     uint16_t entity_instance_num,
				     uint16_t container_id,
				     uint32_t bmc_record_handle)
{
	uint32_t size = sizeof(struct pldm_pdr_hdr) +
			sizeof(struct pldm_pdr_fru_record_set);
	uint8_t data[size];

	struct pldm_pdr_hdr *hdr = (struct pldm_pdr_hdr *)&data;
	hdr->version = 1;
	hdr->record_handle = bmc_record_handle;
	hdr->type = PLDM_PDR_FRU_RECORD_SET;
	hdr->record_change_num = 0;
	hdr->length = htole16(sizeof(struct pldm_pdr_fru_record_set));
	struct pldm_pdr_fru_record_set *fru =
		(struct pldm_pdr_fru_record_set *)((uint8_t *)hdr +
						   sizeof(struct pldm_pdr_hdr));
	fru->terminus_handle = htole16(terminus_handle);
	fru->fru_rsi = htole16(fru_rsi);
	fru->entity_type = htole16(entity_type);
	fru->entity_instance_num = htole16(entity_instance_num);
	fru->container_id = htole16(container_id);

	return pldm_pdr_add(repo, data, size, bmc_record_handle, false,
			    terminus_handle);
}

const pldm_pdr_record *pldm_pdr_fru_record_set_find_by_rsi(
	const pldm_pdr *repo, uint16_t fru_rsi, uint16_t *terminus_handle,
	uint16_t *entity_type, uint16_t *entity_instance_num,
	uint16_t *container_id)
{
	assert(terminus_handle != NULL);
	assert(entity_type != NULL);
	assert(entity_instance_num != NULL);
	assert(container_id != NULL);

	uint8_t *data = NULL;
	uint32_t size = 0;
	const pldm_pdr_record *curr_record = pldm_pdr_find_record_by_type(
		repo, PLDM_PDR_FRU_RECORD_SET, NULL, &data, &size);
	while (curr_record != NULL) {
		struct pldm_pdr_fru_record_set *fru =
			(struct pldm_pdr_fru_record_set
				 *)(data + sizeof(struct pldm_pdr_hdr));
		if (fru->fru_rsi == htole16(fru_rsi)) {
			*terminus_handle = le16toh(fru->terminus_handle);
			*entity_type = le16toh(fru->entity_type);
			*entity_instance_num =
				le16toh(fru->entity_instance_num);
			*container_id = le16toh(fru->container_id);
			return curr_record;
		}
		data = NULL;
		curr_record = pldm_pdr_find_record_by_type(
			repo, PLDM_PDR_FRU_RECORD_SET, curr_record, &data,
			&size);
	}

	*terminus_handle = 0;
	*entity_type = 0;
	*entity_instance_num = 0;
	*container_id = 0;

	return NULL;
}

/* NOLINTNEXTLINE(readability-identifier-naming) */
void pldm_pdr_update_TL_pdr(const pldm_pdr *repo, uint16_t terminus_handle,
			    uint8_t tid, uint8_t tl_eid, bool valid_bit)
{
	uint8_t *out_data = NULL;
	uint32_t size = 0;
	const pldm_pdr_record *record;
	record = pldm_pdr_find_record_by_type(repo, PLDM_TERMINUS_LOCATOR_PDR,
					      NULL, &out_data, &size);

	do {
		if (record != NULL) {
			struct pldm_terminus_locator_pdr *pdr =
				(struct pldm_terminus_locator_pdr *)out_data;
			struct pldm_terminus_locator_type_mctp_eid *value =
				(struct pldm_terminus_locator_type_mctp_eid *)
					pdr->terminus_locator_value;
			if (pdr->terminus_handle == terminus_handle &&
			    pdr->tid == tid && value->eid == tl_eid) {
				pdr->validity = valid_bit;
				break;
			}
		}
		record = pldm_pdr_find_record_by_type(repo,
						      PLDM_TERMINUS_LOCATOR_PDR,
						      record, &out_data, &size);
	} while (record);
}

typedef struct pldm_entity_association_tree {
	pldm_entity_node *root;
	uint16_t last_used_container_id;
} pldm_entity_association_tree;

typedef struct pldm_entity_node {
	pldm_entity entity;
	pldm_entity parent;
	pldm_entity_node *first_child;
	pldm_entity_node *next_sibling;
	uint8_t association_type;
} pldm_entity_node;

static inline uint16_t next_container_id(pldm_entity_association_tree *tree)
{
	assert(tree != NULL);
	assert(tree->last_used_container_id != UINT16_MAX);

	return ++tree->last_used_container_id;
}

pldm_entity pldm_entity_extract(pldm_entity_node *node)
{
	assert(node != NULL);

	return node->entity;
}

pldm_entity_association_tree *pldm_entity_association_tree_init(void)
{
	pldm_entity_association_tree *tree =
		malloc(sizeof(pldm_entity_association_tree));
	assert(tree != NULL);
	tree->root = NULL;
	tree->last_used_container_id = 0;

	return tree;
}

static pldm_entity_node *find_insertion_at(pldm_entity_node *start,
					   uint16_t entity_type)
{
	assert(start != NULL);

	/* Insert after the the last node that matches the input entity type, or
	 * at the end if no such match occurrs
	 */
	while (start->next_sibling != NULL) {
		uint16_t this_type = start->entity.entity_type;
		pldm_entity_node *next = start->next_sibling;
		if (this_type == entity_type &&
		    (this_type != next->entity.entity_type)) {
			break;
		}
		start = start->next_sibling;
	}

	return start;
}

pldm_entity_node *pldm_entity_association_tree_add(
	pldm_entity_association_tree *tree, pldm_entity *entity,
	uint16_t entity_instance_number, pldm_entity_node *parent,
	uint8_t association_type)
{
	assert(tree != NULL);
	assert(entity != NULL);

	if (entity_instance_number != 0xFFFF && parent != NULL) {
		pldm_entity node;
		node.entity_type = entity->entity_type;
		node.entity_instance_num = entity_instance_number;
		if (pldm_is_current_parent_child(parent, &node)) {
			return NULL;
		}
	}

	assert(association_type == PLDM_ENTITY_ASSOCIAION_PHYSICAL ||
	       association_type == PLDM_ENTITY_ASSOCIAION_LOGICAL);
	pldm_entity_node *node = malloc(sizeof(pldm_entity_node));
	assert(node != NULL);
	node->first_child = NULL;
	node->next_sibling = NULL;
	node->parent.entity_type = 0;
	node->parent.entity_instance_num = 0;
	node->parent.entity_container_id = 0;
	node->entity.entity_type = entity->entity_type;
	node->entity.entity_instance_num =
		entity_instance_number != 0xFFFF ? entity_instance_number : 1;
	node->association_type = association_type;

	if (tree->root == NULL) {
		assert(parent == NULL);
		tree->root = node;
		/* container_id 0 here indicates this is the top-most entry */
		node->entity.entity_container_id = 0;
	} else if (parent != NULL && parent->first_child == NULL) {
		parent->first_child = node;
		node->parent = parent->entity;
		node->entity.entity_container_id = next_container_id(tree);
	} else {
		pldm_entity_node *start = parent == NULL ? tree->root :
							   parent->first_child;
		pldm_entity_node *prev =
			find_insertion_at(start, entity->entity_type);
		assert(prev != NULL);
		pldm_entity_node *next = prev->next_sibling;
		if (prev->entity.entity_type == entity->entity_type) {
			assert(prev->entity.entity_instance_num != UINT16_MAX);
			node->entity.entity_instance_num =
				entity_instance_number != 0xFFFF ?
					entity_instance_number :
					prev->entity.entity_instance_num + 1;
		}
		prev->next_sibling = node;
		node->parent = prev->parent;
		node->next_sibling = next;
		node->entity.entity_container_id =
			prev->entity.entity_container_id;
	}
	entity->entity_instance_num = node->entity.entity_instance_num;
	entity->entity_container_id = node->entity.entity_container_id;

	return node;
}

static void get_num_nodes(pldm_entity_node *node, size_t *num)
{
	if (node == NULL) {
		return;
	}

	++(*num);
	get_num_nodes(node->next_sibling, num);
	get_num_nodes(node->first_child, num);
}

static void entity_association_tree_visit(pldm_entity_node *node,
					  pldm_entity *entities, size_t *index)
{
	if (node == NULL) {
		return;
	}

	pldm_entity *entity = &entities[*index];
	++(*index);
	entity->entity_type = node->entity.entity_type;
	entity->entity_instance_num = node->entity.entity_instance_num;
	entity->entity_container_id = node->entity.entity_container_id;

	entity_association_tree_visit(node->next_sibling, entities, index);
	entity_association_tree_visit(node->first_child, entities, index);
}

void pldm_entity_association_tree_visit(pldm_entity_association_tree *tree,
					pldm_entity **entities, size_t *size)
{
	assert(tree != NULL);

	*size = 0;
	if (tree->root == NULL) {
		return;
	}

	get_num_nodes(tree->root, size);
	*entities = malloc(*size * sizeof(pldm_entity));
	size_t index = 0;
	entity_association_tree_visit(tree->root, *entities, &index);
}

static void entity_association_tree_destroy(pldm_entity_node *node)
{
	if (node == NULL) {
		return;
	}

	entity_association_tree_destroy(node->next_sibling);
	entity_association_tree_destroy(node->first_child);
	free(node);
}

void pldm_entity_association_tree_destroy(pldm_entity_association_tree *tree)
{
	assert(tree != NULL);

	entity_association_tree_destroy(tree->root);
	free(tree);
}

inline bool pldm_entity_is_node_parent(pldm_entity_node *node)
{
	assert(node != NULL);

	return node->first_child != NULL;
}

inline pldm_entity pldm_entity_get_parent(pldm_entity_node *node)
{
	assert(node != NULL);

	return node->parent;
}

inline bool pldm_entity_is_exist_parent(pldm_entity_node *node)
{
	assert(node != NULL);

	if (node->parent.entity_type == 0 &&
	    node->parent.entity_instance_num == 0 &&
	    node->parent.entity_container_id == 0) {
		return false;
	}

	return true;
}

uint8_t pldm_entity_get_num_children(pldm_entity_node *node,
				     uint8_t association_type)
{
	assert(node != NULL);
	assert(association_type == PLDM_ENTITY_ASSOCIAION_PHYSICAL ||
	       association_type == PLDM_ENTITY_ASSOCIAION_LOGICAL);

	size_t count = 0;
	pldm_entity_node *curr = node->first_child;
	while (curr != NULL) {
		if (curr->association_type == association_type) {
			++count;
		}
		curr = curr->next_sibling;
	}

	assert(count < UINT8_MAX);
	return count;
}

bool pldm_is_current_parent_child(pldm_entity_node *parent, pldm_entity *node)
{
	assert(parent != NULL);
	assert(node != NULL);

	pldm_entity_node *curr = parent->first_child;
	while (curr != NULL) {
		if (node->entity_type == curr->entity.entity_type &&
		    node->entity_instance_num ==
			    curr->entity.entity_instance_num) {
			return true;
		}
		curr = curr->next_sibling;
	}

	return false;
}

static void entity_association_pdr_add_children(pldm_entity_node *curr,
						pldm_pdr *repo, uint16_t size,
						uint8_t contained_count,
						uint8_t association_type,
						bool is_remote,
						uint16_t terminus_handle)
{
	uint8_t pdr[size];
	uint8_t *start = pdr;

	struct pldm_pdr_hdr *hdr = (struct pldm_pdr_hdr *)start;
	hdr->version = 1;
	hdr->record_handle = 0;
	hdr->type = PLDM_PDR_ENTITY_ASSOCIATION;
	hdr->record_change_num = 0;
	hdr->length = htole16(size - sizeof(struct pldm_pdr_hdr));
	start += sizeof(struct pldm_pdr_hdr);

	uint16_t *container_id = (uint16_t *)start;
	*container_id = htole16(curr->first_child->entity.entity_container_id);
	start += sizeof(uint16_t);
	*start = association_type;
	start += sizeof(uint8_t);

	pldm_entity *entity = (pldm_entity *)start;
	entity->entity_type = htole16(curr->entity.entity_type);
	entity->entity_instance_num = htole16(curr->entity.entity_instance_num);
	entity->entity_container_id = htole16(curr->entity.entity_container_id);
	start += sizeof(pldm_entity);

	*start = contained_count;
	start += sizeof(uint8_t);

	pldm_entity_node *node = curr->first_child;
	while (node != NULL) {
		if (node->association_type == association_type) {
			pldm_entity *entity = (pldm_entity *)start;
			entity->entity_type = htole16(node->entity.entity_type);
			entity->entity_instance_num =
				htole16(node->entity.entity_instance_num);
			entity->entity_container_id =
				htole16(node->entity.entity_container_id);
			start += sizeof(pldm_entity);
		}
		node = node->next_sibling;
	}

	pldm_pdr_add(repo, pdr, size, 0, is_remote, terminus_handle);
}

static void entity_association_pdr_add_entry(pldm_entity_node *curr,
					     pldm_pdr *repo, bool is_remote,
					     uint16_t terminus_handle)
{
	uint8_t num_logical_children = pldm_entity_get_num_children(
		curr, PLDM_ENTITY_ASSOCIAION_LOGICAL);
	uint8_t num_physical_children = pldm_entity_get_num_children(
		curr, PLDM_ENTITY_ASSOCIAION_PHYSICAL);

	if (num_logical_children) {
		uint16_t logical_pdr_size =
			sizeof(struct pldm_pdr_hdr) + sizeof(uint16_t) +
			sizeof(uint8_t) + sizeof(pldm_entity) +
			sizeof(uint8_t) +
			(num_logical_children * sizeof(pldm_entity));
		entity_association_pdr_add_children(
			curr, repo, logical_pdr_size, num_logical_children,
			PLDM_ENTITY_ASSOCIAION_LOGICAL, is_remote,
			terminus_handle);
	}

	if (num_physical_children) {
		uint16_t physical_pdr_size =
			sizeof(struct pldm_pdr_hdr) + sizeof(uint16_t) +
			sizeof(uint8_t) + sizeof(pldm_entity) +
			sizeof(uint8_t) +
			(num_physical_children * sizeof(pldm_entity));
		entity_association_pdr_add_children(
			curr, repo, physical_pdr_size, num_physical_children,
			PLDM_ENTITY_ASSOCIAION_PHYSICAL, is_remote,
			terminus_handle);
	}
}

bool is_present(pldm_entity entity, pldm_entity **entities, size_t num_entities)
{
	if (entities == NULL || num_entities == 0) {
		return true;
	}
	size_t i = 0;
	while (i < num_entities) {
		if ((*entities + i)->entity_type == entity.entity_type) {
			return true;
		}
		i++;
	}
	return false;
}

static void entity_association_pdr_add(pldm_entity_node *curr, pldm_pdr *repo,
				       pldm_entity **entities,
				       size_t num_entities, bool is_remote,
				       uint16_t terminus_handle)
{
	if (curr == NULL) {
		return;
	}
	bool to_add = true;
	to_add = is_present(curr->entity, entities, num_entities);
	if (to_add) {
		entity_association_pdr_add_entry(curr, repo, is_remote,
						 terminus_handle);
	}
	entity_association_pdr_add(curr->next_sibling, repo, entities,
				   num_entities, is_remote, terminus_handle);
	entity_association_pdr_add(curr->first_child, repo, entities,
				   num_entities, is_remote, terminus_handle);
}

void pldm_entity_association_pdr_add(pldm_entity_association_tree *tree,
				     pldm_pdr *repo, bool is_remote,
				     uint16_t terminus_handle)
{
	assert(tree != NULL);
	assert(repo != NULL);

	entity_association_pdr_add(tree->root, repo, NULL, 0, is_remote,
				   terminus_handle);
}

void pldm_entity_association_pdr_add_from_node(
	pldm_entity_node *node, pldm_pdr *repo, pldm_entity **entities,
	size_t num_entities, bool is_remote, uint16_t terminus_handle)
{
	assert(repo != NULL);

	entity_association_pdr_add(node, repo, entities, num_entities,
				   is_remote, terminus_handle);
}

void find_entity_ref_in_tree(pldm_entity_node *tree_node, pldm_entity entity,
			     pldm_entity_node **node)
{
	if (tree_node == NULL) {
		return;
	}

	if (tree_node->entity.entity_type == entity.entity_type &&
	    tree_node->entity.entity_instance_num ==
		    entity.entity_instance_num) {
		*node = tree_node;
		return;
	}

	find_entity_ref_in_tree(tree_node->first_child, entity, node);
	find_entity_ref_in_tree(tree_node->next_sibling, entity, node);
}

void pldm_find_entity_ref_in_tree(pldm_entity_association_tree *tree,
				  pldm_entity entity, pldm_entity_node **node)
{
	assert(tree != NULL);
	find_entity_ref_in_tree(tree->root, entity, node);
}

void pldm_pdr_remove_pdrs_by_terminus_handle(pldm_pdr *repo,
					     uint16_t terminus_handle)
{
	assert(repo != NULL);
	bool removed = false;

	pldm_pdr_record *record = repo->first;
	pldm_pdr_record *prev = NULL;
	while (record != NULL) {
		pldm_pdr_record *next = record->next;
		if (record->terminus_handle == terminus_handle) {
			if (repo->first == record) {
				repo->first = next;
			} else {
				prev->next = next;
			}
			if (repo->last == record) {
				repo->last = prev;
			}
			if (record->data) {
				free(record->data);
			}
			--repo->record_count;
			repo->size -= record->size;
			free(record);
			removed = true;
		} else {
			prev = record;
		}
		record = next;
	}

	if (removed == true) {
		record = repo->first;
		uint32_t record_handle = 0;
		while (record != NULL) {
			record->record_handle = ++record_handle;
			if (record->data != NULL) {
				struct pldm_pdr_hdr *hdr =
					(struct pldm_pdr_hdr *)(record->data);
				hdr->record_handle =
					htole32(record->record_handle);
			}
			record = record->next;
		}
	}
}
void pldm_pdr_remove_remote_pdrs(pldm_pdr *repo)
{
	assert(repo != NULL);
	bool removed = false;

	pldm_pdr_record *record = repo->first;
	pldm_pdr_record *prev = NULL;
	while (record != NULL) {
		pldm_pdr_record *next = record->next;
		if (record->is_remote == true) {
			if (repo->first == record) {
				repo->first = next;
			} else {
				prev->next = next;
			}
			if (repo->last == record) {
				repo->last = prev;
			}
			if (record->data) {
				free(record->data);
			}
			--repo->record_count;
			repo->size -= record->size;
			free(record);
			removed = true;
		} else {
			prev = record;
		}
		record = next;
	}

	if (removed == true) {
		record = repo->first;
		uint32_t record_handle = 0;
		while (record != NULL) {
			record->record_handle = ++record_handle;
			if (record->data != NULL) {
				struct pldm_pdr_hdr *hdr =
					(struct pldm_pdr_hdr *)(record->data);
				hdr->record_handle =
					htole32(record->record_handle);
			}
			record = record->next;
		}
	}
}

void entity_association_tree_find(pldm_entity_node *node, pldm_entity *entity,
				  pldm_entity_node **out)
{
	if (node == NULL) {
		return;
	}

	if (node->entity.entity_type == entity->entity_type &&
	    node->entity.entity_instance_num == entity->entity_instance_num) {
		entity->entity_container_id = node->entity.entity_container_id;
		*out = node;
		return;
	}

	entity_association_tree_find(node->next_sibling, entity, out);
	entity_association_tree_find(node->first_child, entity, out);
}

pldm_entity_node *
pldm_entity_association_tree_find(pldm_entity_association_tree *tree,
				  pldm_entity *entity)
{
	assert(tree != NULL);

	pldm_entity_node *node = NULL;
	entity_association_tree_find(tree->root, entity, &node);
	return node;
}

static void entity_association_tree_copy(pldm_entity_node *org_node,
					 pldm_entity_node **new_node)
{
	if (org_node == NULL) {
		return;
	}
	*new_node = malloc(sizeof(pldm_entity_node));
	(*new_node)->parent = org_node->parent;
	(*new_node)->entity = org_node->entity;
	(*new_node)->association_type = org_node->association_type;
	(*new_node)->first_child = NULL;
	(*new_node)->next_sibling = NULL;
	entity_association_tree_copy(org_node->first_child,
				     &((*new_node)->first_child));
	entity_association_tree_copy(org_node->next_sibling,
				     &((*new_node)->next_sibling));
}

void pldm_entity_association_tree_copy_root(
	pldm_entity_association_tree *org_tree,
	pldm_entity_association_tree *new_tree)
{
	new_tree->last_used_container_id = org_tree->last_used_container_id;
	entity_association_tree_copy(org_tree->root, &(new_tree->root));
}

void pldm_entity_association_tree_destroy_root(
	pldm_entity_association_tree *tree)
{
	assert(tree != NULL);
	entity_association_tree_destroy(tree->root);
	tree->last_used_container_id = 0;
	tree->root = NULL;
}

bool pldm_is_empty_entity_assoc_tree(pldm_entity_association_tree *tree)
{
	return ((tree->root == NULL) ? true : false);
}

void pldm_entity_association_pdr_extract(const uint8_t *pdr, uint16_t pdr_len,
					 size_t *num_entities,
					 pldm_entity **entities)
{
	assert(pdr != NULL);
	assert(pdr_len >= sizeof(struct pldm_pdr_hdr) +
				  sizeof(struct pldm_pdr_entity_association));

	struct pldm_pdr_hdr *hdr = (struct pldm_pdr_hdr *)pdr;
	assert(hdr->type == PLDM_PDR_ENTITY_ASSOCIATION);

	const uint8_t *start = (uint8_t *)pdr;
	const uint8_t *end =
		start + sizeof(struct pldm_pdr_hdr) + le16toh(hdr->length);
	start += sizeof(struct pldm_pdr_hdr);
	struct pldm_pdr_entity_association *entity_association_pdr =
		(struct pldm_pdr_entity_association *)start;
	*num_entities = entity_association_pdr->num_children + 1;
	assert(*num_entities >= 2);
	*entities = malloc(sizeof(pldm_entity) * *num_entities);
	assert(*entities != NULL);
	assert(start + sizeof(struct pldm_pdr_entity_association) +
		       sizeof(pldm_entity) * (*num_entities - 2) ==
	       end);
	(*entities)->entity_type =
		le16toh(entity_association_pdr->container.entity_type);
	(*entities)->entity_instance_num =
		le16toh(entity_association_pdr->container.entity_instance_num);
	(*entities)->entity_container_id =
		le16toh(entity_association_pdr->container.entity_container_id);
	pldm_entity *curr_entity = entity_association_pdr->children;
	size_t i = 1;
	while (i < *num_entities) {
		(*entities + i)->entity_type =
			le16toh(curr_entity->entity_type);
		(*entities + i)->entity_instance_num =
			le16toh(curr_entity->entity_instance_num);
		(*entities + i)->entity_container_id =
			le16toh(curr_entity->entity_container_id);
		++curr_entity;
		++i;
	}
}
