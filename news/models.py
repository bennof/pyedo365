from datetime import date

from django.db import models
from wagtail.snippets.models import register_snippet

from wagtail.core.fields import RichTextField
from wagtail.admin.edit_handlers import FieldPanel
from wagtail.images.edit_handlers import ImageChooserPanel


@register_snippet
class Date(models.Model):
    date = models.DateField("Date", default=date.today)
    title = models.CharField(max_length=250)
    body = RichTextField(blank=True,max_length=500)
    image = models.ForeignKey(
        'wagtailimages.Image', null=True, blank=True,
        on_delete=models.SET_NULL, related_name='+'
    )

    panels = [
        FieldPanel('date'),
        FieldPanel('title'),
        FieldPanel('body', classname="full"),
        ImageChooserPanel('image'),
    ]

    @staticmethod
    def get_next(self):
        Date.objects.filter(date__gte=date.today()).order_by("date")[:5]

    def __str__(self):
        return self.title

    class Meta:
        verbose_name_plural = 'Calendar'
