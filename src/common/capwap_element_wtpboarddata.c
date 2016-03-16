#include "capwap.h"
#include "capwap_array.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Vendor Identifier                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Board Data Sub-Element...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Board Data Type        |       Board Data Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Board Data Value...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   38 for WTP Board Data

Length:   >=14

********************************************************************/

/* */
static void capwap_wtpboarddata_element_create(void *data,
					       capwap_message_elements_handle handle,
					       struct capwap_write_message_elements_ops *func)
{
	struct capwap_wtpboarddata_element *element =
		(struct capwap_wtpboarddata_element *)data;
	struct capwap_wtpboarddata_board_subelement* desc;

	ASSERT(data != NULL);
	ASSERT(element->vendor != 0);
	ASSERT(!cds_list_empty(&element->boardsubelement));

	/* */
	func->write_u32(handle, element->vendor);

	/* */
	cds_list_for_each_entry(desc, &element->boardsubelement, node) {
		ASSERT((desc->type >= CAPWAP_BOARD_SUBELEMENT_TYPE_FIRST) &&
		       (desc->type <= CAPWAP_BOARD_SUBELEMENT_TYPE_LAST));
		ASSERT((desc->length > 0) &&
		       (desc->length <= CAPWAP_BOARD_SUBELEMENT_MAXDATA));

		func->write_u16(handle, desc->type);
		func->write_u16(handle, desc->length);
		func->write_block(handle, desc->data, desc->length);
	}
}

/* */
static void *capwap_wtpboarddata_element_clone(void *data)
{
	struct capwap_wtpboarddata_element *cloneelement;
	struct capwap_wtpboarddata_element *element =
		(struct capwap_wtpboarddata_element *)data;
	struct capwap_wtpboarddata_board_subelement* desc;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_wtpboarddata_element));
	CDS_INIT_LIST_HEAD(&cloneelement->boardsubelement);

	cds_list_for_each_entry(desc, &element->boardsubelement, node) {
		struct capwap_wtpboarddata_board_subelement *clone;

		clone = capwap_clone(desc, sizeof(struct capwap_wtpboarddata_board_subelement) + desc->length);
		cds_list_add_tail(&clone->node, &cloneelement->boardsubelement);
	}

	return cloneelement;
}

/* */
static void capwap_wtpboarddata_element_free(void *data)
{
	struct capwap_wtpboarddata_element *element =
		(struct capwap_wtpboarddata_element *)data;
	struct capwap_wtpboarddata_board_subelement* desc, *d;

	ASSERT(data != NULL);

	/* */
	cds_list_for_each_entry_safe(desc, d, &element->boardsubelement, node) {
		cds_list_del(&desc->node);
		capwap_free(desc);
	}

	capwap_free(data);
}

/* */
static void *capwap_wtpboarddata_element_parsing(capwap_message_elements_handle handle,
						 struct capwap_read_message_elements_ops *func)
{
	struct capwap_wtpboarddata_element *data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) < 14) {
		capwap_logging_debug("Invalid WTP Board Data element: underbuffer");
		return NULL;
	}

	/* */
	data = (struct capwap_wtpboarddata_element *)capwap_alloc(sizeof(struct capwap_wtpboarddata_element));
	CDS_INIT_LIST_HEAD(&data->boardsubelement);

	/* Retrieve data */
	func->read_u32(handle, &data->vendor);
	if (!data->vendor) {
		capwap_wtpboarddata_element_free((void*)data);
		capwap_logging_debug("Invalid WTP Board Data element: invalid vendor");
		return NULL;
	}

	/* WTP Board Data Subelement */
	while (func->read_ready(handle) > 0) {
		uint16_t type;
		uint16_t length;
		struct capwap_wtpboarddata_board_subelement *desc;

		/* */
		func->read_u16(handle, &type);
		func->read_u16(handle, &length);

		if (type < CAPWAP_BOARD_SUBELEMENT_TYPE_FIRST ||
		    type > CAPWAP_BOARD_SUBELEMENT_TYPE_LAST) {
			capwap_logging_debug("Invalid WTP Board Data element: invalid type");
			capwap_wtpboarddata_element_free(data);
			return NULL;
		}

		/* Check buffer size */
		if (!length ||
		    length > CAPWAP_BOARD_SUBELEMENT_MAXDATA ||
		    length != func->read_ready(handle)) {
			capwap_logging_debug("Invalid WTP Board Data element: invalid length");
			capwap_wtpboarddata_element_free(data);
			return NULL;
		}

		desc = capwap_alloc(sizeof(struct capwap_wtpboarddata_board_subelement) + length);
		desc->type = type;
		desc->length = length;
		func->read_block(handle, desc->data, length);

		cds_list_add_tail(&desc->node, &data->boardsubelement);
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_wtpboarddata_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_wtpboarddata_element_create,
	.parse = capwap_wtpboarddata_element_parsing,
	.clone = capwap_wtpboarddata_element_clone,
	.free = capwap_wtpboarddata_element_free
};

/* */
struct capwap_wtpboarddata_board_subelement *
capwap_wtpboarddata_get_subelement(struct capwap_wtpboarddata_element *wtpboarddata,
				   int subelement)
{
	struct capwap_wtpboarddata_board_subelement *desc;
	ASSERT(wtpboarddata != NULL);
	ASSERT((subelement >= CAPWAP_BOARD_SUBELEMENT_TYPE_FIRST) &&
	       (subelement <= CAPWAP_BOARD_SUBELEMENT_TYPE_LAST));

	/* */
	cds_list_for_each_entry(desc, &wtpboarddata->boardsubelement, node) {
		if (desc->type == subelement)
			return desc;
	}

	return NULL;
}
