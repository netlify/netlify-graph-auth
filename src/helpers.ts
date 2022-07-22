type error = {
  extensions?: {
    type: string;
    graphQLField?: string;
  };
};

type results = {
  errors?: error[];
  graphQLErrors?: error[];
};

export function findMissingAuthServices(results: results | error[]): string[] {
  /* Detect and normalize between:
    1. The full graphql result
    2. The `result.errors` of a graphql result
    3. Apollo's GraphQL error structure
     */
  let errors: error[] | undefined;

  if (Array.isArray(results)) {
    errors = results;
  } else if (
    results != null &&
    ('errors' in results || 'graphQLErrors' in results)
  ) {
    errors =
      // Full GraphQL result
      results.errors ||
      // Apollo error
      results.graphQLErrors;
  }

  if (!Array.isArray(errors)) {
    return [];
  }

  const missingServiceErrors = errors.filter(
    (error) => error?.extensions?.type === 'auth/missing-auth',
  );

  const missingServices = missingServiceErrors
    .map((error) => error?.extensions?.graphQLField!)
    .filter(Boolean);

  return missingServices;
}
