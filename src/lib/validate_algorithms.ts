const validateAlgorithms = (option: string, algorithms?: number[]) => {
  if (
    algorithms !== undefined &&
    (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== 'number'))
  ) {
    throw new TypeError(`"${option}" option must be an array of numbers`)
  }

  if (!algorithms) {
    return undefined
  }

  return new Set(algorithms)
}

export default validateAlgorithms
