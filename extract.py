import pandas as pd
import ipaddress

input_csv = "Syn.csv"
output_csv = "Syn_extract.csv"
target = "BENIGN"
limit = 30000

def ip_to_int(ip):
    return int(ipaddress.IPv4Address(ip))

def extract_traffic(input_file, output_file=None, target="BENIGN", limit=None):
    """
    Extract data with Label 'xxx' and process it for further analysis.

    Args:
        input_file (str): Input CSV file path.
        output_file (str, optional): Output file path (if saving).
    Returns:
        pd.DataFrame: Processed data.
    """
    # Read CSV file
    df = pd.read_csv(input_file, skipinitialspace=True, low_memory=False)
    df.columns = df.columns.str.strip()

    # # Filter rows with Label 'BENIGN'/'Syn'
    # df = df[df['Label'].str.strip() == target].head(limit)

    # Select required columns
    selected_columns = [
        'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
        'Protocol', 'Timestamp', 'FIN Flag Count', 'SYN Flag Count',
        'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Label'
    ]

    # Check available columns
    available_cols = [col for col in selected_columns if col in df.columns]
    missing_cols = set(selected_columns) - set(available_cols)
    if missing_cols:
        print(f"Warning: The following columns are missing: {missing_cols}")

    result = df[available_cols].copy()

    # Format Source IP and Destination IP
    if 'Source IP' in result.columns:
        result.loc[:, 'Source IP'] = result['Source IP'].apply(ip_to_int)
    if 'Destination IP' in result.columns:
        result.loc[:, 'Destination IP'] = result['Destination IP'].apply(ip_to_int)

    # Convert Timestamp to numeric
    if 'Timestamp' in result.columns:
        result.loc[:, 'Timestamp'] = pd.to_datetime(result['Timestamp']).astype(int) // 10**9

    # Combine flags into one column
    flag_columns = ['FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
                    'PSH Flag Count', 'ACK Flag Count']
    # if all(col in result.columns for col in flag_columns):
    #     result.loc[:, 'Flags'] = result[flag_columns].apply(
    #         lambda row: ''.join(row.astype(str)), axis=1
    #     )
    #     result.loc[:, 'Flags'] = result['Flags'].apply(lambda x: int(x, 2))
    #     result.drop(columns=flag_columns, inplace=True)
    result.loc[:, 'Flags'] = (
        result[flag_columns]
        .astype(str)
        .apply(lambda x: ''.join(x), axis=1)
        .apply(lambda x: int(x, 2))
    )
    result.drop(columns=flag_columns, inplace=True)

    result.loc[:, 'Length'] = result['Total Length of Fwd Packets'] + result['Total Length of Bwd Packets']
    
    result.loc[:, 'Label'] = result['Label'].apply(lambda x: 1 if x == 'Syn' else 0)

    # Save results (if output file is specified)
    if output_file:
        result.to_csv(output_file, index=False)
        print(f"Results saved to: {output_file}")

    return result

# Example usage
traffic = extract_traffic(input_csv, output_csv, target, limit)

# Display preview
print("\nProcessed results preview:")
print(traffic.head())