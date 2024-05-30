export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const log = (...args: any[]) => {
  const date = new Date();
  const time = [date.getHours(), date.getMinutes(), date.getSeconds()]
    .map((x) => x.toString().padStart(2, '0'))
    .join(':');

  console.log(`[${time}]`, ...args);
};

export const getAbi = (arch: string) => {
  const abis = new Map([
    ['arm64', 'arm64-v8a'],
    ['arm', 'armeabi-v7a'],
    ['x86', 'x86'],
    ['x64', 'x86_64'],
  ]);

  return abis.get(arch);
};
