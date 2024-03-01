/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-namespace */
/* eslint-disable @typescript-eslint/ban-types */
/* eslint-disable-next-line @typescript-eslint/no-namespace */
export { };

interface CustomMatchers<R = unknown> {
  toThrowErrorMatching(expected: Function, message: string | RegExp): Promise<R>;
}

declare global {
  namespace jest {
    interface Expect extends CustomMatchers { }
    interface Matchers<R> extends CustomMatchers<R> { }
    interface InverseAsymmetricMatchers extends CustomMatchers { }
  }
}

const matchString = (received: string, expected: string | RegExp): boolean => {
  if (typeof expected === 'string') {
    return received === expected;
  }
  return expected.test(received);
};

expect.extend({
  toThrowErrorMatching(error: Error | undefined | Function, type: Function, message: string | RegExp) {
    if (typeof error === 'function') {
      const func = error;
      error = undefined;
      try {
        func();
      } catch (err: Error | any) {
        error = err;
      }
    }

    if (typeof error === 'undefined') {
      return {
        pass: false,
        message: () => `Expected ${this.utils.printExpected(type.name)}\nReceived: nothing`
      }
    }

    if (!(error instanceof type)) {
      return {
        pass: false,
        // @ts-ignore
        message: () => `Expected ${this.utils.printExpected(type.name)}\nReceived: ${this.utils.printReceived(error.name)}`
      }
    }

    if (!matchString((error as Error).message, message)) {
      return {
        pass: false,
        // @ts-ignore
        message: () => `Expected ${this.utils.printExpected(message)}\nReceived: ${this.utils.printReceived(error.message)}`
      }
    }

    return {
      pass: true,
      // @ts-ignore
      message: () => `Expected ${this.utils.printExpected(type.name)}\nReceived: ${this.utils.printReceived(error.name)}`
    };
  },
});

