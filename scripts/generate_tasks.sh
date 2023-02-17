#!/bin/bash
# curl -L https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Kubernetes_V1R8_STIG.zip > Kubernetes_STIG.zip
# unzip -o -j Kubernetes_STIG.zip  '*/*.xml'
xq '.' U_Kubernetes_STIG*.xml | jq --slurpfile rules rules.json --arg path_suffix "_path" --arg dir_suffix "_dir" '
.Benchmark.Group
  | sort_by(.Rule.version)
  | map(select([.Rule.version] | inside($rules[0].manual) | not))
  | map(.name =
    .Rule.version + " | "
    + .Rule."@severity" + " | "
    + (.Rule.title | gsub("[\r\n]+"; "") | gsub(" +"; " ")))
  | map(.when = "rule_" + (.Rule.version | gsub("-"; "_") | ascii_downcase))
  | map(.tags += ["rule_" + (.Rule.version|gsub("-"; "_"))])
  | map(
      def path_title: .Rule.title | capture("Kubernetes(?<file>.*)?must"; "gp").file | gsub("^\\s+|\\s+$";"");
      def path_is_plural: (
        (path_title | test("kubelet\\s+configuration\\s+files"; "gp") | not) and
        ((path_title | test("component.*$"; "gp")) or
        (path_title | test("(.*)(s|es)$"; "gp")) or
        (path_title | test("etcd"; "gp")) or
        (path_title | test("PKI"; "gp")))
      );
      def path_var: (path_title | capture("^(?:component )?(?<file>.*?)(?:\\s+file|\\s+files)?$"; "gp").file | gsub("^\\s+|\\s+$";"") | gsub("\\.|\\s+";"_") | gsub("configuration";"config") | ascii_downcase)
        + (if path_is_plural then $dir_suffix else $path_suffix end);
      def path_permissions: (.Rule.title | capture("set\\s+to\\s+(?<mode>\\d{3})"; "gp").mode);
      def path_name: (
        if (path_title | test("PKI\\s+keys"; "gp")) then
          ("*.key")
        elif (path_title | test("PKI"; "gp")) then
          ("*.crt")
        elif (path_is_plural) then
          ("*")
        else ("{{ \(path_var) | basename }}")
        end);
      def owner: .Rule.title | capture("owned\\s+by\\s+(?<owner>.*)\\."; "gp").owner;
      def assignment_pattern: "(?:value\\s+of|argument|and\\s+set)\\s+\\\"(?<flag>.*)\\\"\\s+to:?\\s+(?:either\\s+|a\\s+minimum\\s+of\\s+|a\\s+maximum\\s+of\\s+|a\\s+value\\s+of\\s+|include\\s+|greater\\s+than\\s+|.*following\\s+content:\\s*)?(?:(?:(?:```(?<extension>[\\w]+\\s+))|\\\")(?<value>.*)(?:(?:```)|\\\"))?";
      def file_type: .Rule.fixtext["#text"] | capture("Edit\\s+the\\s+(?<type>.*?(?:policy|manifest)?)\\s+file"; "gp").type | ascii_downcase | gsub("\\.|\\s+";"_";"gp") | ltrimstr("kubernetes_");
      def upgrade_component: .Rule.fixtext["#text"] | capture("Upgrade\\s+.*(?<component>kubectl|Kubernetes)"; "gp").component;
      def upgrade_packages: if (upgrade_component == "Kubernetes") then ["kubelet", "kubeadm", "kubectl"] else ["kubectl"] end;
      if .Rule.title | test("file\\s+permissions|least\\s+privileges"; "gp") then
        .block = [
          {
            "name": "\(.Rule.version) | \(path_var) | Find file permissions",
            "ansible.builtin.command": "find {{ \(path_var) }} -name \"\(path_name)\" -type f -exec stat -c %a {} \\;",
            "register": "permission_output",
            "check_mode": "no",
            "when": "rule_\(.Rule.version | gsub("-"; "_") | ascii_downcase)"
          },
          {
            "name": "\(.Rule.version) | \(path_var) | Debug",
            "ansible.builtin.debug": {"msg": "{{ permission_output }}"}
          },
          {
            "name": "\(.Rule.version) | \(path_var) | Assert permissions are correct",
            "ansible.builtin.assert": {
              "that": [
                (if path_is_plural then
                    "permission_output.stdout_lines|list|map(\"int\")|min <= \(path_permissions)"
                  else
                    true
                end)
              ]
            }
          },
          {
            "name": "\(.Rule.version) | \(path_var) | Set file permissions",
            "ansible.builtin.file": {
              "path": ("{{ \(path_var) }}"),
              "mode": .Rule.title | match("([0-9]{3})").string,
              "state": (if path_is_plural then "directory" else "file" end),
              "recurse": path_is_plural
            }
          }
        ]
      elif .Rule.title | test("must\\s+be\\s+owned\\s+by"; "gp") then
        .["ansible.builtin.file"] = {
          "path": ("{{ \(path_var) }}"),
          "state": (if path_is_plural then "directory" else "file" end),
          "recurse": path_is_plural,
          "owner": owner,
          "group": owner
        }
      elif (.Rule.fixtext["#text"] | test("Edit\\s+(?:the\\s+Kubernetes|any\\s+manifest)"; "gp")) then
        if (.Rule.fixtext["#text"] | test("\\s+[sS]et\\s+(the)?"; "gp")) then
          if (.Rule.fixtext["#text"] | test("following\\s+content:"; "gp")) then
            # TODO - Block
            .["ansible.builtin.copy"] = {
              dest: "{{ \(file_type)_path }}",
              content: (.Rule.fixtext["#text"] | capture(assignment_pattern; "gp").value),
              owner: "root",
              group: "root",
              mode: "0644",
              backup: true,
            }
            # TODO - lineinfile value path to file above
          elif (.Rule.fixtext["#text"] | test("any\\s+manifest";"gp")) then
            .block = [
              {
                "name": "\(.Rule.version) | API Server | \(.Rule.title)",
                "ansible.builtin.lineinfile": {
                  "dest": "{{ controller_manager_manifest_path }}",
                  "backup": true,
                  "backrefs": true,
                  "state": "present",
                  "regexp": "^(\\s+- \(
                      .Rule.fixtext["#text"]
                      | capture(assignment_pattern;"gp").flag | gsub("[\\n\\s]+";" ")
                    )=(?!.*\(
                      .Rule.fixtext["#text"]
                      | capture(assignment_pattern;"gp").value
                    ).*)$)",
                  "line": "\\1,\(.Rule.fixtext["#text"] | capture(assignment_pattern;"gp").value)",
                  "insertafter": "^\\s+- etcd$"
                }
              },
              {
                "name": "\(.Rule.version) | API Server | \(.Rule.title)",
                "ansible.builtin.lineinfile": {
                  "dest": "{{ api_server_manifest_path }}",
                  "backup": true,
                  "backrefs": true,
                  "state": "present",
                  "regexp": "^(\\s+- \(
                      .Rule.fixtext["#text"]
                      | capture(assignment_pattern;"gp").flag | gsub("[\\n\\s]+";" ")
                    )=(?!.*\(
                      .Rule.fixtext["#text"]
                      | capture(assignment_pattern;"gp").value
                    ).*)$)",
                  "line": "\\1,\(.Rule.fixtext["#text"] | capture(assignment_pattern;"gp").value)",
                  "insertafter": "^\\s+- etcd$"
                }
              },
              {
                "name": "\(.Rule.version) | API Server | \(.Rule.title)",
                "ansible.builtin.lineinfile": {
                  "dest": "{{ scheduler_manifest_path }}",
                  "backup": true,
                  "backrefs": true,
                  "state": "present",
                  "regexp": "^(\\s+- \(
                      .Rule.fixtext["#text"]
                      | capture(assignment_pattern;"gp").flag | gsub("[\\n\\s]+";" ")
                    )=(?!.*\(
                      .Rule.fixtext["#text"]
                      | capture(assignment_pattern;"gp").value
                    ).*)$)",
                  "line": "\\1,\(.Rule.fixtext["#text"] | capture(assignment_pattern;"gp").value)",
                  "insertafter": "^\\s+- etcd$"
                }
              },
              {
                "name": "\(.Rule.version) | API Server | \(.Rule.title)",
                "ansible.builtin.lineinfile": {
                  "dest": "{{ etcd_manifest_path }}",
                  "backup": true,
                  "backrefs": true,
                  "state": "present",
                  "regexp": "^(\\s+- \(
                      .Rule.fixtext["#text"]
                      | capture(assignment_pattern;"gp").flag | gsub("[\\n\\s]+";" ")
                    )=(?!.*\(
                      .Rule.fixtext["#text"]
                      | capture(assignment_pattern;"gp").value
                    ).*)$)",
                  "line": "\\1,\(.Rule.fixtext["#text"] | capture(assignment_pattern;"gp").value)",
                  "insertafter": "^\\s+- etcd$"
                }
              }
              # TODO - optionally append kubelet config?
            ]
          else
            .["ansible.builtin.lineinfile"] = {
              "dest": "{{ \(file_type)_path }}",
              "backup": true,
              "backrefs": true,
              "state": "present",
              "regexp": "^(\\s+- \(
                  .Rule.fixtext["#text"]
                  | capture(assignment_pattern;"gp").flag | gsub("[\\n\\s]+";" ")
                )=(?!.*\(
                  .Rule.fixtext["#text"]
                  | capture(assignment_pattern;"gp").value
                ).*)$)",
              "line": "\\1,\(.Rule.fixtext["#text"] | capture(assignment_pattern;"gp").value)",
              "insertafter": "^\\s+- etcd$"
            }
          end
       elif (.Rule.fixtext["#text"] | test("[rR]emove\\s+"; "gp")) then
          .["ansible.builtin.lineinfile"] = {
            "dest": "{{ api_server_manifest_path }}",
            "backup": true,
            "state": "absent",
            "regexp": "^(\\s+- \(
              .Rule.fixtext["#text"]
              | capture("Remove\\s+(the\\s+setting|parameter)\\s+\\\"(?<flag>.*)\\\"").flag
              )=.*$"
          }
        elif (.Rule.fixtext["#text"] | test("to\\s+look\\s+like\\s+the\\s+following"; "gp")) then
          .["ansible.builtin.copy"] = {
            src: "files/\(file_type | ltrimstr("kubernetes-"))",
            dest: "{{ \(file_type)_path }}",
            owner: "root",
            group: "root",
            mode: "0644",
            backup: true,
          }
        else
          .error = {
            "contains": "Edit the Kubernetes",
            "msg": (.Rule.fixtext["#text"] | gsub("[\\t\\r\\n\\s]+";" "; "gp"))
          }
        end
      elif (.Rule.fixtext["#text"] | test("^Upgrade\\s+"; "gp")) then
        . += {
          "ansible.builtin.yum": {
            "name": "{{ packages }}",
            "state": "latest",
            "update_only": true,
            "update_cache": true
          },
          "vars": {
            "packages": upgrade_packages
          }
        }
      else .["ansible.builtin.debug"] = {
        "msg": (.Rule.fixtext["#text"] | gsub("[\\t\\r\\n\\s]+";" "))
      }
      end
    )
  | map(
    def tag_names: $rules[0].tags | keys;
    reduce tag_names[] as $tag_name (.;
    if ([.Rule.version] | inside($rules[0].tags[$tag_name])) then
      .tags += [$tag_name]
    else
      .
    end)
    )
  | map(del(.Rule))
  | map(del(.title))
  | map(del(."@id"))
  | map(del(.description))
  | map(del(.Rule.id))' | yq '.' -y > tasks/stig.yml
