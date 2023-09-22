import * as fs from 'fs';
import merge from 'lodash.merge';
import path from 'path';



const tsconfigs = [];

let tsConfigPath = process.argv[2];
let tsConfig = JSON.parse(fs.readFileSync(tsConfigPath, 'utf8'));
tsconfigs.push(tsConfig);

while(tsConfig.extends) {
  tsConfigPath = path.resolve(path.dirname(tsConfigPath), tsConfig.extends);
  tsConfig = JSON.parse(fs.readFileSync(tsConfigPath, 'utf8'));
  tsconfigs.push(tsConfig);
}

tsConfig = merge({}, ...tsconfigs.reverse());
const result = {};

if (tsConfig.compilerOptions.module.startsWith('ES')) {
  result.type = 'module';
}

result.imports = tsConfig.compilerOptions.paths;

console.log(JSON.stringify(result, null, 2));

process.exit(0);
