def expand_fasta(input_file, output_file, multiplier):
    """
    Expand a FASTA file by repeating its sequences.

    :param input_file: Path to the input FASTA file
    :param output_file: Path to the output FASTA file
    :param multiplier: How many times to repeat the sequences
    """
    with open(input_file, "r") as infile, open(output_file, "w") as outfile:
        header = ""
        sequence = []
        for line in infile:
            if line.startswith(">"):
                if header:
                    # Write previous sequence
                    repeated_sequence = '\n'.join(sequence) * multiplier
                    # print(repeated_sequence)
                    outfile.write(header)
                    outfile.write(repeated_sequence + "\n")
                # Start new sequence
                header = line
                sequence = []
            else:
                sequence.append(line.strip())
        # Write the last sequence
        repeated_sequence = '\n'.join(sequence) * multiplier
        # print(repeated_sequence)
        outfile.write(header)
        outfile.write(repeated_sequence + "\n")
    print(f"Expanded FASTA file saved as '{output_file}'")

# Example usage
#input_file = "large_bacillus_subtilis_128.fasta"  # Input file (original)
#output_file = "large_bacillus_subtilis.fasta"  # Output file

input_file = "original.fasta"  # Input file (original)
output_file = "large_bacillus_subtilis_128.fasta"  # Output file

#multiplier = 2  # Adjust to increase file size
multiplier = 25  # Adjust to increase file size

expand_fasta(input_file, output_file, multiplier)

