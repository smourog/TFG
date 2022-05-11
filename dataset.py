import pefile
import csv
import os
import sys
import json

malware = 'F:/UNI/TFG/Dataset/malware/'
benign = 'F:/UNI/TFG/Dataset/benign/'

packers_sections = {
    # The packer/protector/tools section names/keywords
    '.aspack': 'Aspack packer',
    '.adata': 'Aspack packer/Armadillo packer',
    'ASPack': 'Aspack packer',
    '.ASPack': 'ASPAck Protector',
    '.boom': 'The Boomerang List Builder (config+exe xored with a single byte key 0x77)',
    '.ccg': 'CCG Packer (Chinese Packer)',
    '.charmve': 'Added by the PIN tool',
    'BitArts': 'Crunch 2.0 Packer',
    'DAStub': 'DAStub Dragon Armor protector',
    '!EPack': 'Epack packer',
    'FSG!': 'FSG packer (not a section name, but a good identifier)',
    '.gentee': 'Gentee installer',
    'kkrunchy': 'kkrunchy Packer',
    '.mackt': 'ImpRec-created section',
    '.MaskPE': 'MaskPE Packer',
    'MEW': 'MEW packer',
    '.MPRESS1': 'Mpress Packer',
    '.MPRESS2': 'Mpress Packer',
    '.neolite': 'Neolite Packer',
    '.neolit': 'Neolite Packer',
    '.nsp1': 'NsPack packer',
    '.nsp0': 'NsPack packer',
    '.nsp2': 'NsPack packer',
    'nsp1': 'NsPack packer',
    'nsp0': 'NsPack packer',
    'nsp2': 'NsPack packer',
    '.packed': 'RLPack Packer (first section)',
    'pebundle': 'PEBundle Packer',
    'PEBundle': 'PEBundle Packer',
    'PEC2TO': 'PECompact packer',
    'PECompact2': 'PECompact packer (not a section name, but a good identifier)',
    'PEC2': 'PECompact packer',
    'pec1': 'PECompact packer',
    'pec2': 'PECompact packer',
    'PEC2MO': 'PECompact packer',
    'PELOCKnt': 'PELock Protector',
    '.perplex': 'Perplex PE-Protector',
    'PESHiELD': 'PEShield Packer',
    '.petite': 'Petite Packer',
    'petite': 'Petite Packer',
    '.pinclie': 'Added by the PIN tool',
    'ProCrypt': 'ProCrypt Packer',
    '.RLPack': 'RLPack Packer (second section)',
    '.rmnet': 'Ramnit virus marker',
    'RCryptor': 'RPCrypt Packer',
    '.RPCrypt': 'RPCrypt Packer',
    '.seau': 'SeauSFX Packer',
    '.sforce3': 'StarForce Protection',
    '.spack': 'Simple Pack (by bagie)',
    '.svkp': 'SVKP packer',
    'Themida': 'Themida Packer',
    '.Themida': 'Themida Packer',
    'Themida ': 'Themida Packer',
    '.taz': 'Some version os PESpin',
    '.tsuarch': 'TSULoader',
    '.tsustub': 'TSULoader',
    '.packed': 'Unknown Packer',
    'PEPACK!!': 'Pepack',
    '.Upack': 'Upack packer',
    '.ByDwing': 'Upack Packer',
    'UPX0': 'UPX packer',
    'UPX1': 'UPX packer',
    'UPX2': 'UPX packer',
    'UPX!': 'UPX packer',
    '.UPX0': 'UPX Packer',
    '.UPX1': 'UPX Packer',
    '.UPX2': 'UPX Packer',
    '.vmp0': 'VMProtect packer',
    '.vmp1': 'VMProtect packer',
    '.vmp2': 'VMProtect packer',
    'VProtect': 'Vprotect Packer',
    '.winapi': 'Added by API Override tool',
    'WinLicen': 'WinLicense (Themida) Protector',
    '_winzip_': 'WinZip Self-Extractor',
    '.WWPACK': 'WWPACK Packer',
    '.yP': 'Y0da Protector',
    '.y0da': 'Y0da Protector',
}

packers_sections_lower = {x.lower(): x for x in packers_sections.keys()}


def detect_packing(sections_of_pe):
    return [packers_sections_lower[x.lower()] for x in sections_of_pe if x.lower() in packers_sections_lower.keys()]


def c_json(name, pe, malware):

    # count_suspicious_functions = 0
    number_packers = 0

    entropy = map(lambda x: x.get_entropy(), pe.sections)
    raw_sizes = map(lambda x: x.SizeOfRawData, pe.sections)
    virtual_sizes = map(lambda x: x.Misc_VirtualSize, pe.sections)
    physical_address = map(lambda x: x.Misc_PhysicalAddress, pe.sections)
    virtual_address = map(lambda x: x.VirtualAddress, pe.sections)
    pointer_raw_data = map(lambda x: x.PointerToRawData, pe.sections)
    characteristics = map(lambda x: x.Characteristics, pe.sections)

    data = {'Name': name,
            'e_magic': pe.DOS_HEADER.e_magic,
            'e_cblp': pe.DOS_HEADER.e_cblp,
            'e_cp': pe.DOS_HEADER.e_cp,
            'e_crlc': pe.DOS_HEADER.e_crlc,
            'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
            'e_minalloc': pe.DOS_HEADER.e_minalloc,
            'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
            'e_ss': pe.DOS_HEADER.e_ss,
            'e_sp': pe.DOS_HEADER.e_sp,
            'e_csum': pe.DOS_HEADER.e_csum,
            'e_ip': pe.DOS_HEADER.e_ip,
            'e_cs': pe.DOS_HEADER.e_cs,
            'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
            'e_ovno': pe.DOS_HEADER.e_ovno,
            'e_oemid': pe.DOS_HEADER.e_oemid,
            'e_oeminfo': pe.DOS_HEADER.e_oeminfo,
            'e_lfanew': pe.DOS_HEADER.e_lfanew,
            'Machine': pe.FILE_HEADER.Machine,
            'NumberOfSections': pe.FILE_HEADER.NumberOfSections,
            'TimeDateStamp': pe.FILE_HEADER.TimeDateStamp,
            'PointerToSymbolTable': pe.FILE_HEADER.PointerToSymbolTable,
            'NumberOfSymbols': pe.FILE_HEADER.NumberOfSymbols,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'Magic': pe.OPTIONAL_HEADER.Magic,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
            'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
            'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
            'Malware': malware
            }
    # if sys.argv[0] == 'train':
    #     data['Malware'] = malware

    # try:
    #     for entry in pe.DIRECTORY_ENTRY_IMPORT:
    #         for func in entry.imports:
    #             if func.name.decode('utf-8') in content:
    #                 count_suspicious_functions += 1
    #     data['SuspiciousImportFunctions'] = count_suspicious_functions
    # except AttributeError:
    #     data['SuspiciousImportFunctions'] = 0

    try:
        matches = detect_packing([
            section.Name.decode(errors='replace',).rstrip('\x00') for section in pe.sections
        ])
        number_packers = len(matches)

        data['SuspiciousNameSection'] = number_packers
    except AttributeError as e:
        data['SuspiciousNameSection'] = 0
    try:
        data['SectionsLength'] = len(pe.sections)
    except (ValueError, TypeError):
        data['SectionsLength'] = 0
    try:
        data['SectionMinEntropy'] = min(entropy)
    except (ValueError, TypeError):
        data['SectionMinEntropy'] = 0
    try:
        data['SectionMaxEntropy'] = max(entropy)
    except (ValueError, TypeError):
        data['SectionMaxEntropy'] = 0
    try:
        data['SectionMinRawsize'] = min(raw_sizes)
    except (ValueError, TypeError):
        data['SectionMinRawsize'] = 0
    try:
        data['SectionMaxRawsize'] = max(raw_sizes)
    except (ValueError, TypeError):
        data['SectionMaxRawsize'] = 0
    try:
        data['SectionMinVirtualsize'] = min(virtual_sizes)
    except (ValueError, TypeError):
        data['SectionMinVirtualsize'] = 0
    try:
        data['SectionMaxVirtualsize'] = max(virtual_sizes)
    except (ValueError, TypeError):
        data['SectionMaxVirtualsize'] = 0
    try:
        data['SectionMaxVirtualsize'] = max(virtual_sizes)
    except (ValueError, TypeError):
        data['SectionMaxVirtualsize'] = 0

    try:
        data['SectionMaxPhysical'] = max(physical_address)
    except (ValueError, TypeError):
        data['SectionMaxPhysical'] = 0
    try:
        data['SectionMinPhysical'] = min(physical_address)
    except (ValueError, TypeError):
        data['SectionMinPhysical'] = 0

    try:
        data['SectionMaxVirtual'] = max(virtual_address)
    except (ValueError, TypeError):
        data['SectionMaxVirtual'] = 0
    try:
        data['SectionMinVirtual'] = min(virtual_address)
    except (ValueError, TypeError):
        data['SectionMinVirtual'] = 0

    try:
        data['SectionMaxPointerData'] = max(pointer_raw_data)
    except (ValueError, TypeError):
        data['SectionMaxPointerData'] = 0

    try:
        data['SectionMinPointerData'] = min(pointer_raw_data)
    except (ValueError, TypeError):
        data['SectionMinPointerData'] = 0

    try:
        data['SectionMaxChar'] = max(characteristics)
    except (ValueError, TypeError):
        data['SectionMaxChar'] = 0

    try:
        data['SectionMinChar'] = min(characteristics)
    except (ValueError, TypeError):
        data['SectionMainChar'] = 0

    try:
        data['DirectoryEntryImport'] = (len(pe.DIRECTORY_ENTRY_IMPORT))
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        data['DirectoryEntryImportSize'] = (len(imports))
    except AttributeError:
        data['DirectoryEntryImport'] = 0
        data['DirectoryEntryImportSize'] = 0
    # Exports
    try:
        data['DirectoryEntryExport'] = (len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
    except AttributeError:
        # No export
        data['DirectoryEntryExport'] = 0

    data['ImageDirectoryEntryExport'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].VirtualAddress
    data['ImageDirectoryEntryImport'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
    data['ImageDirectoryEntryResource'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].VirtualAddress
    data['ImageDirectoryEntryException'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']].VirtualAddress
    data['ImageDirectoryEntrySecurity'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

    return data

    # finally let's parse the exe file with pefile and get sections names


path_m = 'dataset_malware.csv'
path_b = 'dataset_benign.csv'
with open(path_m, 'w') as csvfile:
    try:
        files = os.listdir(benign)
        p_json = c_json('test', pefile.PE(
            benign + files[0], fast_load=True), 0)
        fieldnames = p_json.keys()
        print(fieldnames)
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for filename in os.listdir(malware):
            try:
                pe = pefile.PE(malware + filename)
                writer.writerow(c_json(filename, pe, 1))
            except Exception as e:
                print(e)
    except Exception as e:
        print(e)

with open(path_b, 'w') as csvfile:
    try:
        files = os.listdir(benign)
        p_json = c_json('test', pefile.PE(
            benign + files[0], fast_load=True), 0)
        fieldnames = p_json.keys()
        print(fieldnames)
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for filename in os.listdir(benign):
            try:
                pe = pefile.PE(benign + filename)
                writer.writerow(c_json(filename, pe, 0))
            except Exception as e:
                print(e)
    except Exception as e:
        print(e)
