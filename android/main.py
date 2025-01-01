import functools
import socket
import time
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import flet as ft

SETTING_URL = 'knock.server_url'
SETTING_SECRET = 'knock.server_secret'
N_ATTEMPTS = 3


class PortStatus(ft.Column):
    def __init__(self, page, server_host):
        super().__init__()
        self.page = page
        self.server_host = server_host
        self.controls = []
        self.update_status()

    def update_status(self):
        assert self.page is not None
        self.page.run_thread(self.check_status)

    def check_status(self):
        assert self.page is not None

        self.controls = [ft.ProgressRing()]
        self.page.update()

        is_open = False
        for _ in range(N_ATTEMPTS):
            try:
                socket.create_connection((self.server_host, 22), timeout=1)
                is_open = True
                break
            except OSError as e:
                print(e)
                time.sleep(1)

        if is_open:
            self.controls = [ft.Text('OPEN', bgcolor='green')]
        else:
            self.controls = [ft.Text('CLOSED', bgcolor='red')]
        self.page.update()


def main(page: ft.Page):
    page.title = 'Knock'

    def knock(event: ft.ControlEvent, server_url, server_secret, status_control):
        event.control.disabled = True
        event.control.update()

        def display_error(error_text):
            def on_dismiss(_):
                page.close(dialog)
                event.control.disabled = False
                event.control.update()

            dialog = ft.AlertDialog(
                modal=True,
                title=ft.Text('Connection error'),
                content=ft.Text(error_text),
                on_dismiss=on_dismiss,
                actions=[
                    ft.TextButton('Close', on_click=on_dismiss),
                ],
            )
            page.open(dialog)

        try:
            request = Request(server_url, method='POST', headers={'authorization': f'bearer {server_secret}'})
            with urlopen(request):
                status_control.update_status()

            event.control.disabled = False
            event.control.update()
        except Exception as e:
            display_error(str(e))

    def server_url_is_valid(url):
        parsed_url = urlparse(url)
        return parsed_url.scheme == 'https' and parsed_url.netloc

    def set_server_url(event: ft.ControlEvent):
        url = event.data
        if not server_url_is_valid(url):
            event.control.error_text = 'Invalid url'
        else:
            page.client_storage.set(SETTING_URL, url)
            event.control.error_text = None
        event.control.update()

    def set_server_secret(event: ft.ControlEvent):
        page.client_storage.set(SETTING_SECRET, event.data)

    def route_change(route):
        page.views.clear()

        main_controls = [
            ft.AppBar(
                title=ft.Text('Knock'),
                bgcolor=ft.colors.SURFACE_VARIANT,
                actions=[
                    ft.PopupMenuButton(
                        items=[
                            ft.PopupMenuItem(text='Settings', on_click=lambda _: page.go('/settings')),
                        ]
                    )
                ],
            ),
        ]
        server_url = page.client_storage.get(SETTING_URL) or ''
        server_secret = page.client_storage.get(SETTING_SECRET) or ''
        if not server_url or not server_url_is_valid(server_url):
            main_controls.extend(
                [
                    ft.Text(value='No server configured'),
                    ft.ElevatedButton('Settings', on_click=lambda _: page.go('/settings')),
                ]
            )
        else:
            parsed_url = urlparse(server_url)
            server_host = parsed_url.netloc
            status_control = PortStatus(page, server_host)
            main_controls.append(
                ft.Row(
                    [
                        ft.Text(value=server_host),
                        status_control,
                        ft.IconButton(
                            icon=ft.icons.REFRESH, tooltip='Refresh', on_click=lambda _: status_control.update_status()
                        ),
                        ft.ElevatedButton(
                            'Knock',
                            on_click=functools.partial(
                                knock, server_url=server_url, server_secret=server_secret, status_control=status_control
                            ),
                        ),
                    ]
                )
            )

        page.views.append(
            ft.View(
                '/',
                main_controls,
            )
        )
        if page.route == '/settings':
            page.views.append(
                ft.View(
                    '/settings',
                    [
                        ft.AppBar(title=ft.Text('Settings'), bgcolor=ft.colors.SURFACE_VARIANT),
                        ft.TextField(label='Server url', value=server_url, on_change=set_server_url),
                        ft.TextField(
                            label='Server secret',
                            value=server_secret,
                            password=True,
                            can_reveal_password=True,
                            on_change=set_server_secret,
                        ),
                    ],
                )
            )
        page.update()

    def view_pop(view):
        page.views.pop()
        top_view = page.views[-1]
        page.go(top_view.route)

    server_url = page.client_storage.get(SETTING_URL) or ''
    if not server_url or not server_url_is_valid(server_url):
        page.route = '/settings'

    page.on_route_change = route_change
    page.on_view_pop = view_pop
    page.go(page.route)


ft.app(main)
