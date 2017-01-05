from __future__ import (absolute_import, division, print_function)
from ansible.plugins.action import ActionBase
from ansible.module_utils._text import to_text

import os
import urlparse
__metaclass__ = type

# Much of this plugin was derrived from the net_template plugin, a part of
# Ansible.


class ActionModule(ActionBase):

    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)
        result['changed'] = False

        try:
            self._handle_template()
        except (ValueError, AttributeError) as exc:
            return dict(failed=True, msg=exc.message)

        result.update(self._execute_module(module_name=self._task.action,
                                           module_args=self._task.args,
                                           task_vars=task_vars))

        return result

    def _get_working_path(self):
        cwd = self._loader.get_basedir()
        if self._task._role is not None:
            cwd = self._task._role._role_path
        return cwd

    def _handle_template(self):
        src = self._task.args.get('src')
        if not src:
            raise ValueError('missing required arguments: src')

        working_path = self._get_working_path()

        if os.path.isabs(src) or urlparse.urlsplit(src).scheme:
            source = src
        else:
            source = self._loader.path_dwim_relative(working_path, 'templates',
                                                     src)
            if not source:
                source = self._loader.path_dwim_relative(working_path, src)

        if not os.path.exists(source):
            return

        try:
            with open(source, 'r') as f:
                template_data = to_text(f.read())
        except IOError:
            return dict(failed=True, msg='unable to load src file')

        searchpath = [working_path]
        if self._task._role is not None:
            searchpath.append(self._task._role._role_path)
            if hasattr(self._task, "_block:"):
                dep_chain = self._task._block.get_dep_chain()
                if dep_chain is not None:
                    for role in dep_chain:
                        searchpath.append(role._role_path)
        searchpath.append(os.path.dirname(source))
        self._templar.environment.loader.searchpath = searchpath
        self._task.args['src'] = self._templar.template(template_data)
