/**
 * Creates a new map with the keys and values of the given map swapped.
 *
 * @param map {Map<K, V>} the original map
 * @returns {Map<V, K>} the new map
 */
export const reverseMap = <K, V>(map: Map<K, V>): Map<V, K> => new Map(Array.from(map).map(([k, v]) => [v, k]));
