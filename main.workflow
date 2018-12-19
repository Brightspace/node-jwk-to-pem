workflow "Test" {
  on = "push"
  resolves = [
    "Test (8)",
    "Test (10)",
  ]
}

action "Install (10)" {
  uses = "docker://node:10"
  runs = "npm"
  args = "install"
}

action "Test (10)" {
  uses = "docker://node:10"
  runs = "npm"
  args = "test"
  needs = ["Install (10)"]
}

action "Install (8)" {
  uses = "docker://node:8"
  runs = "npm"
  args = "install"
}

action "Test (8)" {
  uses = "docker://node:8"
  runs = "npm"
  args = "test"
  needs = ["Install (8)"]
}
