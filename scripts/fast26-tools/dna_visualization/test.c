#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Function to transform DNA sequence using the "squiggle" method
void transform_squiggle(const char *sequence, double **x_out, double **y_out, long long *n_points) {
    long long length = strlen(sequence);

    // Allocate memory for x and y coordinates
    double *x = (double *)malloc((2 * length + 1) * sizeof(double));
    double *y = (double *)malloc((2 * length + 1) * sizeof(double));
    printf("%lld\n", length);


    if (x == NULL || y == NULL) {
        perror("Memory allocation failed");
        exit(1);
    }

    // Initialize x and y coordinates
    double running_value = 0.0;
    x[0] = 0.0;
    y[0] = 0.0;

    // Generate X coordinates
    for (int i = 1; i <= 2 * length; i++) {
        x[i] = x[i - 1] + 0.5;
    }

    // Generate Y coordinates based on DNA sequence
    int index = 1, ret_length = 0;
    for (int i = 0; i < length; i++) {
        char character = sequence[i];
        if (character == 'A') {
            y[index++] = running_value + 0.5;
            y[index++] = running_value;
        } else if (character == 'C') {
            y[index++] = running_value - 0.5;
            y[index++] = running_value;
        } else if (character == 'T') {
            y[index++] = running_value - 0.5;
            y[index++] = running_value - 1.0;
            running_value -= 1.0;
        } else if (character == 'G') {
            y[index++] = running_value + 0.5;
            y[index++] = running_value + 1.0;
            running_value += 1.0;
        } else {
		continue;
	}

	ret_length += 2;
    }

    // Set output pointers and number of points
    *x_out = x;
    *y_out = y;
    *n_points = ret_length + 1;
}

// Function to transform a DNA sequence into x, y coordinates
void transform(const char *sequence, double **x_out, double **y_out, int *n_points) {
    int length = strlen(sequence);

    // Allocate memory for x and y arrays
    double *x = (double *)malloc((length + 1) * sizeof(double));
    double *y = (double *)malloc((length + 1) * sizeof(double));

    if (x == NULL || y == NULL) {
        perror("Memory allocation failed");
        exit(1);
    }

    // Initialize starting point
    x[0] = 0.0;
    y[0] = 0.0;

    // Variables for the current position
    double curr_x = 0.0;
    double curr_y = 0.0;

    // Transformation rules for each base
    for (int i = 0; i < length; i++) {
        switch (sequence[i]) {
            case 'A':
                curr_x += 1.0;
                break;
            case 'T':
                curr_x -= 1.0;
                break;
            case 'G':
                curr_y += 1.0;
                break;
            case 'C':
                curr_y -= 1.0;
                break;
            default:
                fprintf(stderr, "Invalid character in sequence: %c\n", sequence[i]);
                free(x);
                free(y);
                exit(1);
        }
        x[i + 1] = curr_x;
        y[i + 1] = curr_y;
    }

    *x_out = x;
    *y_out = y;
    *n_points = length + 1;
}

// Function to filter out invalid characters
char *filter_sequence(const char *data) {
    int length = strlen(data);
    char *filtered = (char *)malloc(length + 1);

    if (filtered == NULL) {
        perror("Memory allocation failed");
        exit(1);
    }

    int j = 0;
    for (int i = 0; i < length; i++) {
        if (data[i] == 'A' || data[i] == 'T' || data[i] == 'G' || data[i] == 'C') {
            filtered[j++] = data[i];
        }
    }
    filtered[j] = '\0'; // Null-terminate the filtered string

    return filtered;
}

void visualize(const char *fasta_file) {
    // Measure start time
    clock_t start = clock();

    // Open the file
    FILE *file = fopen(fasta_file, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Read the file content
    fseek(file, 0, SEEK_END);
    long long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = (char *)malloc(file_size + 1);
    if (data == NULL) {
        perror("Memory allocation failed");
        fclose(file);
        return;
    }

    fread(data, 1, file_size, file);
    data[file_size] = '\0'; // Null-terminate the string
    fclose(file);

    // Filter the data to keep only 'A', 'T', 'G', 'C'
    // char *filtered_data = filter_sequence(data);

    // Transform the filtered data
    double *x, *y;
    long long n_points;
    // transform(filtered_data, &x, &y, &n_points);
    transform_squiggle(data, &x, &y, &n_points);
    

    // Measure end time
    clock_t end = clock();
    double latency = (double)(end - start) / CLOCKS_PER_SEC;

    // Output results
    printf("File: %s, Latency: %.2f seconds\n", fasta_file, latency);
//    printf("Coordinates:\n");
/*
    for (int i = 0; i < n_points; i++) {
        printf("(%f, %f)\n", x[i], y[i]);
    }
*/

    // Free allocated memory
    free(data);
    // free(filtered_data);
    free(x);
    free(y);
}

#if 0
int main() {
    // Visualize a specific FASTA file
    visualize("large_bacillus_subtilis.fasta");
    /*
    double *x, *y;
    int n_points;

    transform_squiggle("ATA TAT", &x, &y, &n_points);
    for (int i = 0; i < n_points; i++) {
        printf("%f ", x[i]);
    }
    printf("\n");
    for (int i = 0; i < n_points; i++) {
        printf("%f ", y[i]);
    }
    printf("\n");

    free(x);
    free(y);

    */
    return 0;
}
#endif 

int main(int argc, char *argv[]) {
    // Check if the file name is provided as a command-line argument
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_fasta_file>\n", argv[0]);
        return 1;
    }

    // Use the file name from the command-line arguments
    const char *fasta_file = argv[1];

    // Visualize the specified FASTA file
    visualize(fasta_file);

    return 0;
}
