import elftools.elf.elffile as elffile
import elftools.elf.constants as constants

def print_registers(core_file):
    with open(core_file, 'rb') as f:
        elf = elffile.ELFFile(f)

        notesec = None
        for section in elf.iter_sections():
            if "note" in section.name:
                notesec = section

        if notesec is None:
            return 1

        # Find PRSTATUS note in section notes
        for note in notesec.iter_notes():
            if note['n_type'] == "NT_PRSTATUS":
                # Access the register values from the note data
                print(note)
                print(note.keys())
                reg_values = note['n_desc']['pr_reg']
                print(reg_values)
                for reg_name, reg_value in reg_values.items():
                    print(f"{reg_name}: {reg_value:#x}")

if __name__ == "__main__":
    core_file = "core.10807"  # Replace with the path to your core dump
    print_registers(core_file)
