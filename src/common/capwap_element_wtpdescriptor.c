#include <urcu.h>               /* Userspace RCU flavor */
#include <urcu/rculist.h>       /* RCU list */
#include <urcu/compiler.h>      /* For CAA_ARRAY_SIZE */

#include "capwap.h"
#include "capwap_array.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Max Radios  | Radios in use |  Num Encrypt  |Encryp Sub-Elmt|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Encryption Sub-Element    |    Descriptor Sub-Element...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Resvd|  WBID   |  Encryption Capabilities      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Descriptor Vendor Identifier                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Descriptor Type        |       Descriptor Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Descriptor Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   39 for WTP Descriptor

Length:   >= 33

********************************************************************/

/* */
static void capwap_wtpdescriptor_element_create(void *data,
						capwap_message_elements_handle handle,
						struct capwap_write_message_elements_ops *func)
{
	struct capwap_wtpdescriptor_element *element = (struct capwap_wtpdescriptor_element *)data;
	struct capwap_wtpdescriptor_encrypt_subelement *enc;
	struct capwap_wtpdescriptor_desc_subelement *desc;
	uint8_t cnt;

	ASSERT(data != NULL);
	ASSERT(element->maxradios >= element->radiosinuse);
	ASSERT(!cds_list_empty(&element->encryptsubelement));
	ASSERT(!cds_list_empty(&element->descsubelement));

	/* */
	func->write_u8(handle, element->maxradios);
	func->write_u8(handle, element->radiosinuse);

	cnt = 0;
	cds_list_for_each_entry(enc, &element->encryptsubelement, node)
		cnt++;
	func->write_u8(handle, cnt);

	/* */
	cds_list_for_each_entry(enc, &element->encryptsubelement, node) {
		ASSERT((enc->wbid & CAPWAP_WTPDESC_SUBELEMENT_WBID_MASK) == enc->wbid);

		func->write_u8(handle, enc->wbid);
		func->write_u16(handle, enc->capabilities);
	}

	/* */
	cds_list_for_each_entry(desc, &element->descsubelement, node) {
		uint16_t length;

		ASSERT((desc->type >= CAPWAP_WTPDESC_SUBELEMENT_TYPE_FIRST) &&
		       (desc->type <= CAPWAP_WTPDESC_SUBELEMENT_TYPE_LAST));

		length = strlen((char*)desc->data);
		ASSERT(length > 0);

		func->write_u32(handle, desc->vendor);
		func->write_u16(handle, desc->type);
		func->write_u16(handle, length);
		func->write_block(handle, desc->data, length);
	}
}

/* */
static void* capwap_wtpdescriptor_element_clone(void *data)
{
	struct capwap_wtpdescriptor_element *cloneelement;
	struct capwap_wtpdescriptor_element *element = (struct capwap_wtpdescriptor_element *)data;
	struct capwap_wtpdescriptor_encrypt_subelement *enc;
	struct capwap_wtpdescriptor_desc_subelement *desc;

	ASSERT(data != NULL);

	cloneelement = capwap_clone(data, sizeof(struct capwap_wtpdescriptor_element));

	CDS_INIT_LIST_HEAD(&cloneelement->encryptsubelement);
	CDS_INIT_LIST_HEAD(&cloneelement->descsubelement);

	cds_list_for_each_entry(enc, &element->encryptsubelement, node) {
		struct capwap_wtpdescriptor_encrypt_subelement *clone;

		clone = capwap_alloc(sizeof(struct capwap_wtpdescriptor_encrypt_subelement));
		memcpy(clone, enc, sizeof(struct capwap_wtpdescriptor_encrypt_subelement));
		cds_list_add_tail(&clone->node, &cloneelement->encryptsubelement);
	}

	cds_list_for_each_entry(desc, &element->descsubelement, node) {
		struct capwap_wtpdescriptor_desc_subelement *clone;

		clone = capwap_alloc(sizeof(struct capwap_wtpdescriptor_desc_subelement));
		memcpy(clone, desc, sizeof(struct capwap_wtpdescriptor_desc_subelement));
		if (desc->data)
			clone->data = (uint8_t*)capwap_duplicate_string((char*)desc->data);
		cds_list_add_tail(&clone->node, &cloneelement->descsubelement);
	}

	return cloneelement;
}

/* */
static void capwap_wtpdescriptor_element_free(void *data)
{
	struct capwap_wtpdescriptor_element *element = (struct capwap_wtpdescriptor_element *)data;
	struct capwap_wtpdescriptor_encrypt_subelement *enc, *e;
	struct capwap_wtpdescriptor_desc_subelement *desc, *d;

	ASSERT(data != NULL);

	/* */
	cds_list_for_each_entry_safe(enc, e, &element->encryptsubelement, node) {
		cds_list_del(&enc->node);
		capwap_free(enc);
	}

	cds_list_for_each_entry_safe(desc, d, &element->descsubelement, node) {
		cds_list_del(&desc->node);
		if (desc->data)
			capwap_free(desc->data);
		capwap_free(desc);
	}

	capwap_free(data);
}

/* */
static void *capwap_wtpdescriptor_element_parsing(capwap_message_elements_handle handle,
						  struct capwap_read_message_elements_ops *func)
{
	uint8_t i;
	uint8_t encryptlength;
	struct capwap_wtpdescriptor_element* data;

	ASSERT(handle != NULL);
	ASSERT(func != NULL);

	if (func->read_ready(handle) < 33) {
		capwap_logging_debug("Invalid WTP Descriptor element: underbufer");
		return NULL;
	}

	/* */
	data = (struct capwap_wtpdescriptor_element*)capwap_alloc(sizeof(struct capwap_wtpdescriptor_element));
	CDS_INIT_LIST_HEAD(&data->encryptsubelement);
	CDS_INIT_LIST_HEAD(&data->descsubelement);

	/* Retrieve data */
	func->read_u8(handle, &data->maxradios);
	func->read_u8(handle, &data->radiosinuse);
	func->read_u8(handle, &encryptlength);

	/* Check */
	if (!encryptlength) {
		capwap_wtpdescriptor_element_free(data);
		capwap_logging_debug("Invalid WTP Descriptor element: invalid encryptlength");
		return NULL;
	} else if (data->maxradios < data->radiosinuse) {
		capwap_wtpdescriptor_element_free(data);
		capwap_logging_debug("Invalid WTP Descriptor element: invalid radio");
		return NULL;
	}

	/* Encryption Subelement */
	for (i = 0; i < encryptlength; i++) {
		struct capwap_wtpdescriptor_encrypt_subelement* enc;

		/* Check */
		if (func->read_ready(handle) < 3) {
			capwap_logging_debug("Invalid WTP Descriptor subelement: underbuffer");
			capwap_wtpdescriptor_element_free(data);
			return NULL;
		}

		/* */
		enc = capwap_alloc(sizeof(struct capwap_wtpdescriptor_encrypt_subelement));
		func->read_u8(handle, &enc->wbid);
		func->read_u16(handle, &enc->capabilities);

		cds_list_add_tail(&enc->node, &data->encryptsubelement);

		if ((enc->wbid & CAPWAP_WTPDESC_SUBELEMENT_WBID_MASK) != enc->wbid) {
			capwap_wtpdescriptor_element_free(data);
			capwap_logging_debug("Invalid WTP Descriptor element: invalid wbid");
			return NULL;
		}
	}

	/* WTP Description Subelement */
	while (func->read_ready(handle) > 0) {
		unsigned short length;
		uint16_t lengthdesc;
		struct capwap_wtpdescriptor_desc_subelement* desc;

		/* Check */
		if (func->read_ready(handle) < 8) {
			capwap_logging_debug("Invalid WTP Descriptor subelement: underbuffer");
			capwap_wtpdescriptor_element_free(data);
			return NULL;
		}

		/* */
		desc = capwap_alloc(sizeof(struct capwap_wtpdescriptor_desc_subelement));
		func->read_u32(handle, &desc->vendor);
		func->read_u16(handle, &desc->type);
		func->read_u16(handle, &lengthdesc);

		cds_list_add_tail(&desc->node, &data->descsubelement);

		if ((desc->type < CAPWAP_WTPDESC_SUBELEMENT_TYPE_FIRST) ||
		    (desc->type > CAPWAP_WTPDESC_SUBELEMENT_TYPE_LAST)) {
			capwap_logging_debug("Invalid WTP Descriptor subelement: invalid type");
			capwap_wtpdescriptor_element_free(data);
			return NULL;
		}

		/* Check buffer size */
		length = func->read_ready(handle);
		if (!length || (length > CAPWAP_WTPDESC_SUBELEMENT_MAXDATA) || (length < lengthdesc)) {
			capwap_logging_debug("Invalid WTP Descriptor element");
			capwap_wtpdescriptor_element_free(data);
			return NULL;
		}

		desc->data = (uint8_t*)capwap_alloc(lengthdesc + 1);
		func->read_block(handle, desc->data, lengthdesc);
		desc->data[lengthdesc] = 0;
	}

	return data;
}

/* */
const struct capwap_message_elements_ops capwap_element_wtpdescriptor_ops = {
	.category = CAPWAP_MESSAGE_ELEMENT_SINGLE,
	.create = capwap_wtpdescriptor_element_create,
	.parse = capwap_wtpdescriptor_element_parsing,
	.clone = capwap_wtpdescriptor_element_clone,
	.free = capwap_wtpdescriptor_element_free
};
