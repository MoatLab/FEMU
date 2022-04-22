// Misc function and variable declarations.
#ifndef __UTIL_H
#define __UTIL_H

#include "types.h" // u32

// apm.c
void apm_shutdown(void);
struct bregs;
void handle_1553(struct bregs *regs);

// bmp.c
struct bmp_decdata *bmp_alloc(void);
int bmp_decode(struct bmp_decdata *bmp, unsigned char *data, int data_size);
void bmp_get_info(struct bmp_decdata *bmp, int *width, int *height, int *bpp);
int bmp_show(struct bmp_decdata *bmp, unsigned char *pic, int width
             , int height, int depth, int bytes_per_line_dest);

// boot.c
void boot_init(void);
void boot_add_bev(u16 seg, u16 bev, u16 desc, int prio);
void boot_add_bcv(u16 seg, u16 ip, u16 desc, int prio);
struct drive_s;
void boot_add_floppy(struct drive_s *drive_g, const char *desc, int prio);
void boot_add_hd(struct drive_s *drive_g, const char *desc, int prio);
void boot_add_cd(struct drive_s *drive_g, const char *desc, int prio);
void boot_add_cbfs(void *data, const char *desc, int prio);
void interactive_bootmenu(void);
void bcv_prepboot(void);
u8 is_bootprio_strict(void);
struct pci_device;
int bootprio_find_pci_device(struct pci_device *pci);
int bootprio_find_mmio_device(void *mmio);
int bootprio_find_scsi_device(struct pci_device *pci, int target, int lun);
int bootprio_find_scsi_mmio_device(void *mmio, int target, int lun);
int bootprio_find_ata_device(struct pci_device *pci, int chanid, int slave);
int bootprio_find_fdc_device(struct pci_device *pci, int port, int fdid);
int bootprio_find_pci_rom(struct pci_device *pci, int instance);
int bootprio_find_named_rom(const char *name, int instance);
struct usbdevice_s;
int bootprio_find_usb(struct usbdevice_s *usbdev, int lun);
int get_keystroke_full(int msec);
int get_keystroke(int msec);
struct chs_s;
int boot_lchs_find_pci_device(struct pci_device *pci, struct chs_s *chs);
int boot_lchs_find_scsi_device(struct pci_device *pci, int target, int lun,
                               struct chs_s *chs);
int boot_lchs_find_ata_device(struct pci_device *pci, int chanid, int slave,
                              struct chs_s *chs);

// bootsplash.c
void enable_vga_console(void);
void enable_bootsplash(void);
void disable_bootsplash(void);

// cdrom.c
extern struct eltorito_s CDEmu;
extern struct drive_s *cdemu_drive_gf;
struct disk_op_s;
int cdemu_process_op(struct disk_op_s *op);
void cdrom_prepboot(void);
int cdrom_boot(struct drive_s *drive_g);
char *cdrom_media_info(struct drive_s *drive_g);

// clock.c
void clock_setup(void);
void handle_1583(struct bregs *regs);
void clock_poll_irq(void);
u32 irqtimer_calc_ticks(u32 count);
u32 irqtimer_calc(u32 msecs);
int irqtimer_check(u32 end);
void handle_1586(struct bregs *regs);

// fw/acpi.c
void acpi_setup(void);

// fw/biostable.c
void copy_pir(void *pos);
void copy_mptable(void *pos);
extern struct pir_header *PirAddr;
void copy_acpi_rsdp(void *pos);
extern struct rsdp_descriptor *RsdpAddr;
extern u32 acpi_pm1a_cnt;
extern u16 acpi_pm_base;
void *find_acpi_rsdp(void);
void *find_acpi_table(u32 signature);
u32 find_resume_vector(void);
void acpi_reboot(void);
void find_acpi_features(void);
extern struct smbios_entry_point *SMBiosAddr;
struct smbios_entry_point *get_smbios_entry_point();
void copy_smbios(void *pos);
void display_uuid(void);
void copy_table(void *pos);
void smbios_setup(void);

// fw/dsdt_parser.c
struct acpi_device;
void acpi_dsdt_parse(void);
struct acpi_device *acpi_dsdt_find_string(struct acpi_device *prev, const char *hid);
struct acpi_device *acpi_dsdt_find_eisaid(struct acpi_device *prev, u16 eisaid);
char *acpi_dsdt_name(struct acpi_device *dev);
int acpi_dsdt_present_eisaid(u16 eisaid);
int acpi_dsdt_find_io(struct acpi_device *dev, u64 *min, u64 *max);
int acpi_dsdt_find_mem(struct acpi_device *dev, u64 *min, u64 *max);
int acpi_dsdt_find_irq(struct acpi_device *dev, u64 *irq);

// fw/coreboot.c
extern const char *CBvendor, *CBpart;
struct cbfs_file;
void coreboot_debug_putc(char c);
void cbfs_run_payload(struct cbfs_file *file);
void coreboot_platform_setup(void);
void cbfs_payload_setup(void);
void coreboot_preinit(void);
void coreboot_cbfs_init(void);
struct cb_header;
void *find_cb_subtable(struct cb_header *cbh, u32 tag);
struct cb_header *find_cb_table(void);

// fw/csm.c
int csm_bootprio_fdc(struct pci_device *pci, int port, int fdid);
int csm_bootprio_ata(struct pci_device *pci, int chanid, int slave);
int csm_bootprio_pci(struct pci_device *pci);

// fw/mptable.c
void mptable_setup(void);

// fw/mtrr.c
void mtrr_setup(void);

// fw/multiboot.c
void multiboot_init(void);

// fw/pciinit.c
extern u64 pcimem_start, pcimem_end;
extern u64 pcimem64_start, pcimem64_end;
extern const u8 pci_irqs[4];
void pci_setup(void);
void pci_resume(void);

// fw/pirtable.c
void pirtable_setup(void);

// fw/shadow.c
void make_bios_writable(void);
void make_bios_readonly(void);
void qemu_reboot(void);

// fw/smbios.c
void smbios_legacy_setup(void);

// fw/smm.c
void smm_device_setup(void);
void smm_setup(void);

// fw/smp.c
extern u32 MaxCountCPUs;
void wrmsr_smp(u32 index, u64 val);
void smp_setup(void);
void smp_resume(void);
int apic_id_is_present(u8 apic_id);

// hw/dma.c
int dma_floppy(u32 addr, int count, int isWrite);
void dma_setup(void);

// hw/floppy.c
extern struct floppy_ext_dbt_s diskette_param_table2;
void floppy_setup(void);
struct drive_s *init_floppy(int floppyid, int ftype);
int find_floppy_type(u32 size);
int floppy_process_op(struct disk_op_s *op);
void floppy_tick(void);

// hw/ramdisk.c
void ramdisk_setup(void);
int ramdisk_process_op(struct disk_op_s *op);

// hw/sdcard.c
int sdcard_process_op(struct disk_op_s *op);
void sdcard_setup(void);

// hw/timer.c
void timer_setup(void);
void pmtimer_setup(u16 ioport);
void tsctimer_setfreq(u32 khz, const char *src);
u32 timer_calc(u32 msecs);
u32 timer_calc_usec(u32 usecs);
int timer_check(u32 end);
void ndelay(u32 count);
void udelay(u32 count);
void mdelay(u32 count);
void nsleep(u32 count);
void usleep(u32 count);
void msleep(u32 count);
u32 ticks_to_ms(u32 ticks);
u32 ticks_from_ms(u32 ms);
void pit_setup(void);

// jpeg.c
struct jpeg_decdata *jpeg_alloc(void);
int jpeg_decode(struct jpeg_decdata *jpeg, unsigned char *buf);
void jpeg_get_size(struct jpeg_decdata *jpeg, int *width, int *height);
int jpeg_show(struct jpeg_decdata *jpeg, unsigned char *pic, int width
              , int height, int depth, int bytes_per_line_dest);

// kbd.c
void kbd_init(void);
void handle_15c2(struct bregs *regs);
void process_key(u8 key);
u8 enqueue_key(u16 keycode);
u16 ascii_to_keycode(u8 ascii);

// misc.c
extern int HaveRunPost;
extern struct bios_config_table_s BIOS_CONFIG_TABLE __aligned(1);
extern struct floppy_dbt_s diskette_param_table __aligned(1);
extern u8 BiosChecksum;
int in_post(void);
void mathcp_setup(void);

// mouse.c
void mouse_init(void);
void process_mouse(u8 data);

// optionroms.c
struct rom_header;
void callrom(struct rom_header *rom, u16 bdf);
void call_bcv(u16 seg, u16 ip);
int is_pci_vga(struct pci_device *pci);
void optionrom_setup(void);
void vgarom_setup(void);
void s3_resume_vga(void);
extern int ScreenAndDebug;

// pcibios.c
void handle_1ab1(struct bregs *regs);
void bios32_init(void);

// pmm.c
void pmm_init(void);
void pmm_prepboot(void);

// pnpbios.c
u16 get_pnp_offset(void);
void pnp_init(void);

// post.c
void interface_init(void);
void device_hardware_setup(void);
void prepareboot(void);
void startBoot(void);
void reloc_preinit(void *f, void *arg);
void code_mutable_preinit(void);

// sercon.c
void sercon_setup(void);
void sercon_check_event(void);

// serial.c
void serial_setup(void);
void lpt_setup(void);

// version.c
extern const char VERSION[], BUILDINFO[];

// vgahooks.c
void handle_155f(struct bregs *regs);
void handle_157f(struct bregs *regs);
void vgahook_setup(struct pci_device *pci);

#endif // util.h
