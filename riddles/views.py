from django.shortcuts import render

# Create your views here.

from django.views.generic.edit import FormView
from django.contrib.auth.forms import UserCreationForm

from django.shortcuts import get_object_or_404, render, redirect
from .models import Riddle, Option

from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login

from django.http import HttpResponseRedirect
from django.views.generic.base import View
from django.contrib.auth import logout

from django.contrib.auth.forms import PasswordChangeForm


app_url='/riddles/'

def index(request):
    message = None
    if "message" in request.GET:
        message = request.GET["message"]
    return render(
        request,
        "index.html",
        {
            "latest_riddles":
                Riddle.objects.order_by('-pub_date')[:5],
            "message": message

        }
    )

def detail(request, riddle_id):
    error_message = None
    if "error_message" in request.GET:
        error_message = request.GET["error_message"]
    return  render(
        request,
        "answer.html",
        {
            "riddle": get_object_or_404(Riddle, pk=riddle_id),
            "error_message": error_message
        }
    )

def answer(request, riddle_id):
    riddle = get_object_or_404(Riddle, pk=riddle_id)
    try:
        option = riddle.option_set.get(pk=request.POST['option'])
    except (KeyError,Option.DoesNotExist):
        return  redirect (
            '/riddles' + str(riddle_id) +
            '?error_message=Option does not exist',
        )
    else:
        if option.correct:
            return redirect(
                "/riddles/?message=Nice!Choose another one!")
        else:
            return redirect(
                '/riddles/'+str(riddle_id)+
                '?error_message=Wrong Answer!',
            )

class RegisterFormView(FormView):
    form_class = UserCreationForm
    success_url = app_url + "login/"
    template_name = "reg/register.html"
    def form_valid(self, form):
        form.save()
        return super(RegisterFormView, self).form_valid(form)

class LoginFormView(FormView):
    form_class = AuthenticationForm
    template_name = "reg/login.html"
    success_url = app_url
    def form_valid(self, form):
        self.user = form.get_user()
        login(self.request, self.user)
        return super(LoginFormView, self).form_valid(form)

class LogoutView(View):
    def get(self, request):
        logout(request)
        return HttpResponseRedirect(app_url)

class PasswordChangeView(FormView):
    # будем строить на основе
    # встроенной в django формы смены пароля
    form_class = PasswordChangeForm
    template_name = 'reg/password_change_form.html'
    # после смены пароля нужно снова входить
    success_url = app_url + 'login/'
    def get_form_kwargs(self):
        kwargs = super(PasswordChangeView, self).get_form_kwargs()
        kwargs['user'] = self.request.user
        if self.request.method == 'POST':
            kwargs['data'] = self.request.POST
        return kwargs
    def form_valid(self, form):
        form.save()
        return super(PasswordChangeView, self).form_valid(form)

