type error = {
  extensions?: {
    type: string;
    graphQLField?: string;
  };
};

export type MissingAuthService = {graphQLField: string};

export function findMissingAuthServices(
  results: Record<string, unknown> | error[],
): MissingAuthService[] {
  /* Detect and normalize between:
    1. The full graphql result
    2. The `result.errors` of a graphql result
    3. Apollo's GraphQL error structure
     */
  let errors: unknown[] | undefined;

  if (Array.isArray(results)) {
    errors = results;
  } else if (
    results != null &&
    ('errors' in results || 'graphQLErrors' in results)
  ) {
    if (Array.isArray(results.errors)) {
      errors = results.errors; // Full GraphQL result
    } else if (Array.isArray(results.graphQLErrors)) {
      // Apollo error
      errors = results.graphQLErrors;
    }
  }

  if (!Array.isArray(errors)) {
    return [];
  }

  const missingServiceErrors = errors.filter((error) => {
    const isObject = typeof error == 'object' && error != null;

    if (isObject && error.hasOwnProperty('extensions')) {
      // @ts-expect-error
      return error.extensions && error.extensions?.type === 'auth/missing-auth';
    }

    return false;
  });

  const missingServices = missingServiceErrors
    .map((error) => {
      if (
        typeof error == 'object' &&
        error != null &&
        error.hasOwnProperty('extensions')
      ) {
        // @ts-expect-error
        const field = error.extensions?.graphQLField;

        if (field != null) {
          return {graphQLField: field};
        }
      }
    })
    .filter(Boolean) as Array<MissingAuthService>;

  return missingServices;
}
