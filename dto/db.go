package dto

import "time"

type UserPlan struct {
	UserID          string `json:"user_id"`
	RemainingCount  int    `json:"remaining_count"`
	LastRefreshedAt string `json:"last_refreshed_at"`
}

type ResetRemainingCounter struct {
	RemainingCount  int       `json:"remaining_count"`
	LastRefreshedAt time.Time `json:"last_refreshed_at"`
}

type DecrementalUserPlanRemainingCount struct {
	UserID string `json:"user_id"`
}
