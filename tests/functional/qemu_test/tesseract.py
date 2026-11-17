# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2019 Philippe Mathieu-Daudé
'''
Tesseract is an program for doing Optical Character Recognition (OCR),
which can be used in the tests to extract text from screenshots.
'''

import logging
from subprocess import run


def tesseract_ocr(image_path):
    ''' Run the tesseract OCR to extract text from a screenshot '''
    console_logger = logging.getLogger('console')
    console_logger.debug(image_path)
    proc = run(['tesseract', image_path, 'stdout'],
               capture_output=True, encoding='utf8', check=False)
    if proc.returncode:
        return None
    lines = []
    for line in proc.stdout.split('\n'):
        sline = line.strip()
        if len(sline):
            console_logger.debug(sline)
            lines += [sline]
    return lines
