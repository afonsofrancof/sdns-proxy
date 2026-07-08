import csv
import sys
from collections import defaultdict

COLUMNS = ["provider", "protocol", "dnssec_mode", "query_type", "keep_alive"]


def get_uncovered_values(rows, selected_indices, col_indices, all_values):
    covered = defaultdict(set)
    for idx in selected_indices:
        for col, col_idx in col_indices.items():
            covered[col].add(rows[idx][col_idx])
    
    uncovered = {}
    for col in COLUMNS:
        uncovered[col] = all_values[col] - covered[col]
    return uncovered


def main(input_file, output_file):
    with open(input_file, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    col_indices = {col: header.index(col) for col in COLUMNS}

    # Collect all unique values per column
    all_values = defaultdict(set)
    for row in rows:
        for col, idx in col_indices.items():
            all_values[col].add(row[idx])

    # Greedy set cover
    selected = []
    uncovered = get_uncovered_values(rows, selected, col_indices, all_values)

    while any(uncovered.values()):
        best_row = None
        best_score = 0

        for i, row in enumerate(rows):
            if i in selected:
                continue
            score = sum(
                1 for col, idx in col_indices.items() if row[idx] in uncovered[col]
            )
            if score > best_score:
                best_score = score
                best_row = i

        if best_row is None:
            break

        selected.append(best_row)
        uncovered = get_uncovered_values(rows, selected, col_indices, all_values)

    with open(output_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for idx in selected:
            writer.writerow(rows[idx])

    print(f"Selected {len(selected)} rows out of {len(rows)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python minimize_csv.py input.csv output.csv")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
