import bcrypt
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin)
from django.db import models
from django.utils import timezone

from auth_profiles.constants import (
    ADMIN, MAX_LENGTH_VALUES, MAX_LENGTH, MODERATOR, USER)


class UserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Введите email')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            salt = bcrypt.gensalt()
            hash_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            user.password = hash_password.decode('utf-8')
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Должно быть is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Должно быть is_superuser=True')
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):

    STATUS = (
        (USER, 'Пользователь'),
        (MODERATOR, 'Модератор'),
        (ADMIN, 'Админ'),
    )

    email = models.EmailField(
        max_length=MAX_LENGTH,
        verbose_name='Адрес электронной почты',
        db_index=True,
        unique=True)

    first_name = models.CharField(
        max_length=MAX_LENGTH_VALUES,
        verbose_name='Имя',
        blank=True)

    last_name = models.CharField(
        max_length=MAX_LENGTH_VALUES,
        verbose_name='Фамилия',
        blank=True)

    patronymic = models.CharField(
        max_length=MAX_LENGTH_VALUES,
        verbose_name='Отчество',
        blank=True)

    is_active = models.BooleanField(
        default=True,
        verbose_name='Активен')

    is_staff = models.BooleanField(
        default=False,
        verbose_name='Персонал')

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Дата регистрации')

    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name='Дата обновления')

    deleted_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Дата удаления')

    role = models.CharField(
        max_length=max(len(role[0]) for role in STATUS),
        verbose_name='Роль',
        choices=STATUS,
        default=USER)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ('first_name', 'last_name')

    class Meta:
        verbose_name = 'Пользователь'
        verbose_name_plural = 'Пользователи'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.last_name} {self.first_name} {self.patronymic}'

    def user_delete(self):
        self.is_active = False
        self.deleted_at = timezone.now()

    def get_full_name(self):
        return f"{self.last_name} {self.first_name} {self.patronymic}".strip()

    @property
    def is_admin(self):
        return self.role == ADMIN or self.is_superuser

    @property
    def is_moderator(self):
        return self.role == MODERATOR or self.is_admin

    @property
    def is_user(self):
        return self.role == USER and self.is_authenticated
