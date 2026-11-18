"use client";

import { KanbanIcon, ListIcon } from "lucide-react";

import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

export type TaskView = "board" | "list";

export function ViewToggle({ value, onChange }: { value: TaskView; onChange: (v: TaskView) => void }) {
  return (
    <Tabs value={value} onValueChange={(v) => onChange(v as TaskView)}>
      <TabsList>
        <TabsTrigger value="board" aria-label="Board view">
          <KanbanIcon /> Board
        </TabsTrigger>
        <TabsTrigger value="list" aria-label="List view">
          <ListIcon /> List
        </TabsTrigger>
      </TabsList>
    </Tabs>
  );
}
