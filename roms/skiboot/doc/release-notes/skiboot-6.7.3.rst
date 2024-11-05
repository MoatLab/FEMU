.. _skiboot-6.7.3:

==============
skiboot-6.7.3
==============

skiboot 6.7.3 was released on Thursday July 22, 2021. It replaces
:ref:`skiboot-6.7.2` as the current stable release in the 6.7.x series.

It is recommended that 6.7.3 be used instead of 6.7.2 version due to the
bug fixes it contains.

Bug fixes included in this release are:

- pkcs7: pkcs7_get_content_info_type should reset *p on error

- secvar/backend: fix a memory leak in get_pkcs7

- secvar/backend: fix an integer underflow bug

- secvar/backend: Don't overread data in auth descriptor

- secvar: return error if verify_signature runs out of ESLs

- secvar: return error if validate_esl has extra data

- secvar: Make `validate_esl_list` iterate through esl chain

- secvar: ensure ESL buf size is at least what ESL header expects
