import re

# Function to extract links
def find_links_in_file(input_file, output_file):
    # Regular expression pattern for matching http and https URLs
    url_pattern = r'(https?://[^\s]+)'

    # Read the content of the input file
    with open(input_file, 'r') as file:
        file_content = file.read()

    # Find all URLs that match the pattern
    urls = re.findall(url_pattern, file_content)

    # Write the found URLs to the output file
    with open(output_file, 'w') as output:
        for url in urls:
            output.write(url + '\n')

    print(f"Found {len(urls)} links and saved them to {output_file}")

# Input and output file paths
output_file = 'directory-enum.txt'

# Find links in the file and store them in directory-enum.txt
input_file = 'directoty.txt'
find_links_in_file(input_file, output_file)
