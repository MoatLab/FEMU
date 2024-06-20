static struct machine_info CONCAT(machine_, MACHINE)  = {
	.pdc_modelstr = PARISC_MODEL,
	.pdc_model = { PARISC_PDC_MODEL },
	.pdc_version = PARISC_PDC_VERSION,
	.pdc_cpuid = PARISC_PDC_CPUID,
	.pdc_caps = PARISC_PDC_CAPABILITIES,
	.pdc_entry = (unsigned long) PARISC_PDC_ENTRY_ORG,
	.pdc_cache_info = { PARISC_PDC_CACHE_INFO },
	.device_list = { PARISC_DEVICE_LIST },
};

#undef MACHINE
#undef PARISC_MODEL
#undef PARISC_PDC_MODEL
#undef PARISC_PDC_VERSION
#undef PARISC_PDC_CPUID
#undef PARISC_PDC_CAPABILITIES
#undef PARISC_PDC_ENTRY_ORG
#undef PARISC_PDC_CACHE_INFO
#undef PARISC_DEVICE_LIST
