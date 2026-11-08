import fs from 'fs';
import path from 'path';
import solc from 'solc';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const contractPath = path.join(__dirname, 'ThreatRegistry.sol');
const source = fs.readFileSync(contractPath, 'utf8');

const input = {
  language: 'Solidity',
  sources: {
    'ThreatRegistry.sol': {
      content: source,
    },
  },
  settings: {
    optimizer: {
      enabled: true,
      runs: 200,
    },
    outputSelection: {
      '*': {
        '*': ['abi', 'evm.bytecode'],
      },
    },
  },
};

console.log('Compiling ThreatRegistry.sol with solc...');
const output = JSON.parse(solc.compile(JSON.stringify(input)));

if (output.errors) {
  let fatal = false;
  output.errors.forEach((err) => {
    if (err.severity === 'error') {
      console.error(err.formattedMessage);
      fatal = true;
    } else {
      console.warn(err.formattedMessage);
    }
  });
  if (fatal) {
    process.exit(1);
  }
}

const contract = output.contracts['ThreatRegistry.sol']['ThreatRegistry'];
const artifact = {
  contractName: 'ThreatRegistry',
  abi: contract.abi,
  bytecode: contract.evm.bytecode.object,
};

const outputPath = path.join(__dirname, 'ThreatRegistry.json');
fs.writeFileSync(outputPath, JSON.stringify(artifact, null, 2));
console.log(`Compilation successful! Artifact saved to: ${outputPath}`);
