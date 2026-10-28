"""Account admin:  docker compose exec idp flask user add|list|passwd|disable|enable|remove ..."""
import sys

import click
from flask.cli import AppGroup

from .models import Client, User, db


def _password(from_stdin):
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    return click.prompt("Password", hide_input=True, confirmation_prompt=True)


def _get(email):
    user = User.query.filter_by(email=email.strip().lower()).first()
    if not user:
        raise click.ClickException(f"no user {email}")
    return user


def register(app):
    user = AppGroup("user", help="Manage who can sign in.")
    client = AppGroup("client", help="Show the sites that sign in here (edit the clients file to change them).")

    @user.command("add")
    @click.argument("email")
    @click.option("--name", default="")
    @click.option("--password-stdin", is_flag=True, help="Read the password from stdin instead of prompting.")
    def add(email, name, password_stdin):
        email = email.strip().lower()
        if User.query.filter_by(email=email).first():
            raise click.ClickException(f"{email} already exists")
        pw = _password(password_stdin)
        if len(pw) < 12:
            raise click.ClickException("use at least 12 characters")
        u = User(email=email, name=name)
        u.set_password(pw)
        db.session.add(u)
        db.session.commit()
        click.echo(f"added {email}")

    @user.command("list")
    def list_():
        for u in User.query.order_by(User.email):
            click.echo(f"{u.email}\t{u.name}\t{'active' if u.active else 'disabled'}")

    @user.command("passwd")
    @click.argument("email")
    @click.option("--password-stdin", is_flag=True)
    def passwd(email, password_stdin):
        u = _get(email)
        u.set_password(_password(password_stdin))
        db.session.commit()
        click.echo(f"password changed for {u.email}")

    def _set_active(email, active):
        u = _get(email)
        u.active = active
        db.session.commit()
        click.echo(f"{u.email} {'enabled' if active else 'disabled'}")

    user.command("disable")(click.argument("email")(lambda email: _set_active(email, False)))
    user.command("enable")(click.argument("email")(lambda email: _set_active(email, True)))

    @user.command("remove")
    @click.argument("email")
    def remove(email):
        u = _get(email)
        db.session.delete(u)
        db.session.commit()
        click.echo(f"removed {email}")

    @client.command("list")
    def clients():
        for c in Client.query.order_by(Client.client_id):
            click.echo(f"{c.client_id}\t{c.client_name}\t{' '.join(c.redirect_uris)}")

    app.cli.add_command(user)
    app.cli.add_command(client)
