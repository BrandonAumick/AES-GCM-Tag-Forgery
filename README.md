## ⚠️ Warning
This tool is for educational and research purposes only.
Do not use on systems you do not own or have explicit permission to test.

This SageMath tool demonstrates how key information can be recovered when AES-GCM is misused with the same key and IV, and how that can be used to forge authentication tags. The goal of this program is to provide an easy interface to test this forgery concept or use it in CTF scenarios. 3 instances of reuse are required to find the correct values for forgery. Afterwards, any ciphertext based on the same key-IV pair can have it's tag forged.

## How to Run
- Install SageMath to your Linux or WSL environment (No other dependencies needed).

- Download the Sage file directly or clone the repository: `git clone https://github.com/BrandonAumick/AES-GCM-Tag-Forgery.git`

- Run the file in your Sage environment: `sage forge.sage`

- Follow the prompts to input ciphertext-tag pairs, calculate the key values, and use them to forge tags.

- Key values can be saved and loaded to files in the program directory.