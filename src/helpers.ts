export const isJsonString = (value: string): boolean => {
  try {
    JSON.parse(value);
  } catch (e) {
    return false;
  }
  return true;
};

export const jsonParse = (value: string) => {
  try {
    return JSON.parse(value);
  } catch {
    return {};
  }
};
