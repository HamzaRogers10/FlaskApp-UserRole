def paginate_results(query_results, results_list):
    # Paginate the query results

    results = []
    for result in results_list:
        results.append(result)

    while query_results.has_next:
        query_results = query_results.next()
        results_list = []
        for result in query_results.items:
            results_list.append({
                'id': result.id,
                'title': result.title,
                'description': result.description,
                'author_id': result.author_id,
                'created_at': result.created_at,
                'updated_at': result.updated_at
            })
        results.extend(results_list)

    return {
        'results': results,
        'total': query_results.total,
        'page': query_results.page,
        'per_page': query_results.per_page,
        'pages': query_results.pages,
        'prev_page': query_results.prev_num,
        'next_page': query_results.next_num,
    }
