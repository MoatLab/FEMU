/*
 * QTest testcase for PowerNV 10 Seeprom Communications
 *
 * Copyright (c) 2024, IBM Corporation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "libqtest.h"
#include "hw/ssi/pnv_spi_regs.h"
#include "pnv-xscom.h"

#define FLASH_SIZE              (512 * 1024)
#define SPIC2_XSCOM_BASE        0xc0040

/* To transmit READ opcode and address */
#define READ_OP_TDR_DATA        0x0300010000000000
/*
 * N1 shift - tx 4 bytes (transmit opcode and address)
 * N2 shift - tx and rx 8 bytes.
 */
#define READ_OP_COUNTER_CONFIG  0x2040000000002b00
/* SEQ_OP_SELECT_RESPONDER - N1 Shift - N2 Shift * 5 - SEQ_OP_STOP */
#define READ_OP_SEQUENCER       0x1130404040404010

/* To transmit WREN(Set Write Enable Latch in status0 register) opcode */
#define WRITE_OP_WREN           0x0600000000000000
/* To transmit WRITE opcode, address and data */
#define WRITE_OP_TDR_DATA       0x0300010012345678
/* N1 shift - tx 8 bytes (transmit opcode, address and data) */
#define WRITE_OP_COUNTER_CONFIG 0x4000000000002000
/* SEQ_OP_SELECT_RESPONDER - N1 Shift - SEQ_OP_STOP */
#define WRITE_OP_SEQUENCER      0x1130100000000000

static void pnv_spi_xscom_write(QTestState *qts, const PnvChip *chip,
        uint32_t reg, uint64_t val)
{
    uint32_t pcba = SPIC2_XSCOM_BASE + reg;
    qtest_writeq(qts, pnv_xscom_addr(chip, pcba), val);
}

static uint64_t pnv_spi_xscom_read(QTestState *qts, const PnvChip *chip,
        uint32_t reg)
{
    uint32_t pcba = SPIC2_XSCOM_BASE + reg;
    return qtest_readq(qts, pnv_xscom_addr(chip, pcba));
}

static void spi_seeprom_transaction(QTestState *qts, const PnvChip *chip)
{
    /* SPI transactions to SEEPROM to read from SEEPROM image */
    pnv_spi_xscom_write(qts, chip, SPI_CTR_CFG_REG, READ_OP_COUNTER_CONFIG);
    pnv_spi_xscom_write(qts, chip, SPI_SEQ_OP_REG, READ_OP_SEQUENCER);
    pnv_spi_xscom_write(qts, chip, SPI_XMIT_DATA_REG, READ_OP_TDR_DATA);
    pnv_spi_xscom_write(qts, chip, SPI_XMIT_DATA_REG, 0);
    /* Read 5*8 bytes from SEEPROM at 0x100 */
    uint64_t rdr_val = pnv_spi_xscom_read(qts, chip, SPI_RCV_DATA_REG);
    g_test_message("RDR READ = 0x%" PRIx64, rdr_val);
    rdr_val = pnv_spi_xscom_read(qts, chip, SPI_RCV_DATA_REG);
    rdr_val = pnv_spi_xscom_read(qts, chip, SPI_RCV_DATA_REG);
    rdr_val = pnv_spi_xscom_read(qts, chip, SPI_RCV_DATA_REG);
    rdr_val = pnv_spi_xscom_read(qts, chip, SPI_RCV_DATA_REG);
    g_test_message("RDR READ = 0x%" PRIx64, rdr_val);

    /* SPI transactions to SEEPROM to write to SEEPROM image */
    pnv_spi_xscom_write(qts, chip, SPI_CTR_CFG_REG, WRITE_OP_COUNTER_CONFIG);
    /* Set Write Enable Latch bit of status0 register */
    pnv_spi_xscom_write(qts, chip, SPI_SEQ_OP_REG, WRITE_OP_SEQUENCER);
    pnv_spi_xscom_write(qts, chip, SPI_XMIT_DATA_REG, WRITE_OP_WREN);
    /* write 8 bytes to SEEPROM at 0x100 */
    pnv_spi_xscom_write(qts, chip, SPI_SEQ_OP_REG, WRITE_OP_SEQUENCER);
    pnv_spi_xscom_write(qts, chip, SPI_XMIT_DATA_REG, WRITE_OP_TDR_DATA);
}

static void test_spi_seeprom(const void *data)
{
    const PnvChip *chip = data;
    QTestState *qts = NULL;
    g_autofree char *tmp_path = NULL;
    const char *machine = pnv_get_machine_type(chip->chip_type);
    int ret;
    int fd;

    /* Create a temporary raw image */
    fd = g_file_open_tmp("qtest-seeprom-XXXXXX", &tmp_path, NULL);
    g_assert(fd >= 0);
    ret = ftruncate(fd, FLASH_SIZE);
    g_assert(ret == 0);
    close(fd);

    qts = qtest_initf("-machine %s -smp 2,cores=2,"
                      "threads=1 -accel tcg,thread=single -nographic "
                      "-blockdev node-name=pib_spic2,driver=file,"
                      "filename=%s -device 25csm04,bus=chip0.spi.2,cs=0,"
                      "drive=pib_spic2", machine, tmp_path);
    spi_seeprom_transaction(qts, chip);
    qtest_quit(qts);
    unlink(tmp_path);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    for (int i = 0; i < ARRAY_SIZE(pnv_chips); i++) {
        /* TYPE_PNV_SPI is not instantiated for older Power8/9 machines */
        if (pnv_chips[i].chip_type < PNV_CHIP_POWER10) {
            continue;
        }

        g_autofree char *tname = g_strdup_printf("pnv-xscom/spi-seeprom/%s",
                pnv_chips[i].cpu_model);
        qtest_add_data_func(tname, &pnv_chips[i], test_spi_seeprom);
    }
    return g_test_run();
}
