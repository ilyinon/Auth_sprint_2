from django.contrib.postgres.aggregates import ArrayAgg
from django.db.models import Q, Value
from django.db.models.functions import Coalesce
from django.http import JsonResponse
from django.views.generic.detail import BaseDetailView
from django.views.generic.list import BaseListView
from movies.models import FilmWork, Roles

PAGINATE_MOVIES_PER_PAGE = 50


class MoviesApiMixin:
    model = FilmWork
    http_method_names = ["get"]

    def get_queryset(self):
        return FilmWork.objects.values(
            "id", "title", "description", "creation_date", "rating", "type"
        ).annotate(
            genres=ArrayAgg("genres__name", distinct=True),
            actors=Coalesce(
                ArrayAgg(
                    "persons__full_name",
                    filter=Q(personfilmwork__role=Roles.ACTOR),
                    distinct=True,
                ),
                Value([""]),
            ),
            directors=Coalesce(
                ArrayAgg(
                    "persons__full_name",
                    filter=Q(personfilmwork__role=Roles.DIRECTOR),
                    distinct=True,
                ),
                Value([""]),
            ),
            writers=Coalesce(
                ArrayAgg(
                    "persons__full_name",
                    filter=Q(personfilmwork__role=Roles.WRITER),
                    distinct=True,
                ),
                Value([""]),
            ),
        )

    def render_to_response(self, context, **response_kwargs):
        return JsonResponse(context)


class MoviesListApi(MoviesApiMixin, BaseListView):
    http_method_names = ["get"]
    paginate_by = PAGINATE_MOVIES_PER_PAGE

    def get_context_data(self):
        queryset = self.get_queryset()

        paginator, page, queryset, is_paginated = self.paginate_queryset(
            queryset, self.paginate_by
        )

        return {
            "count": paginator.count,
            "total_pages": paginator.num_pages,
            "prev": page.previous_page_number() if page.has_previous() else None,
            "next": page.next_page_number() if page.has_next() else None,
            "results": list(queryset),
        }


class MoviesDetailApi(MoviesApiMixin, BaseDetailView):
    def get_context_data(self, **kwargs) -> JsonResponse:
        return kwargs["object"]
