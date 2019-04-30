### To run the ansible module locally

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e14c95039c2040bf96f0a652a9769dc9)](https://app.codacy.com/app/nomadicj/auth0_ansible?utm_source=github.com&utm_medium=referral&utm_content=nomadicj/auth0_ansible&utm_campaign=Badge_Grade_Dashboard)

- Install python 3.6
- Create a folder named 'local' under group-vars and add main.yml similar to other env and point to 'localhost'
- Create 'local.yml' under inventory folder with host as 'localhost'
- Run ``pip3 install auth0-python hvac deepdiff tenacity``
- Run ``ansible-playbook auth0.yml -vvv -i inventory/local.yml`` from infra/ansible