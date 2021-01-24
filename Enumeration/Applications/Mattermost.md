# Mattermost

[Mattermost](https://mattermost.com/) is an open-source, self-hostable online chat service with file sharing, search, and integrations. It is designed as an internal chat for organisations and companies, and mostly markets itself as an open-source alternative to Slack and Microsoft Teams.

## Configuration

Mattermost configuration settings are maintained in the **config.json** configuration file, located in the **mattermost/config** directory.

There are some interesting information within this file

```bash
# Get the SqlSettings's password
cat /opt/mattermost/config/config.json | grep "DataSource"
```
